package oidcagent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/nexodus-io/nexodus/pkg/ginsession"
	"github.com/nexodus-io/nexodus/pkg/oidcagent/models"
	"golang.org/x/oauth2"
)

const (
	TokenKey   = "token"
	IDTokenKey = "id_token"
)

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (o *OidcAgent) prepareContext(c *gin.Context) context.Context {
	if o.insecureTLS {
		parent := c.Request.Context()
		// #nosec: G402
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: transport}
		return oidc.ClientContext(parent, client)
	}
	return c.Request.Context()
}

// LoginStart initiates the OIDC login process.
// @Summary      Initiates OIDC Web Login
// @Description  Generates state and nonce, then redirects the user to the OAuth2 authorization URL.
// @Id           WebStart
// @Tags         Auth
// @Accepts      json
// @Produce      json
// @Success      200 {object} models.LoginStartResponse
// @Router       /web/login/start [post]
func (o *OidcAgent) LoginStart(c *gin.Context) {
	logger := o.logger
	state, err := randString(16)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	nonce, err := randString(16)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	logger = logger.With(
		"state", state,
		"nonce", nonce,
	)

	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("state", state, int(time.Hour.Seconds()), "/", "", c.Request.URL.Scheme == "https", true)
	c.SetCookie("nonce", nonce, int(time.Hour.Seconds()), "/", "", c.Request.URL.Scheme == "https", true)
	logger.Debug("set cookies")
	c.JSON(http.StatusOK, models.LoginStartResponse{
		AuthorizationRequestURL: o.oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce)),
	})
}

// LoginEnd completes the OIDC login process.
// @Summary      Completes OIDC Web Login
// @Description  Handles the callback from the OAuth2/OpenID provider and verifies the tokens.
// @Id           WebEnd
// @Tags         Auth
// @Accepts      json
// @Produce      json
// @Param        data body models.LoginEndRequest true "End Login"
// @Success      200 {object} models.LoginEndResponse
// @Router       /web/login/end [post]
func (o *OidcAgent) LoginEnd(c *gin.Context) {
	var data models.LoginEndRequest
	var accessToken, refreshToken, rawIDToken string

	err := c.BindJSON(&data)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	requestURL, err := url.Parse(data.RequestURL)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	logger := o.logger
	ctx := o.prepareContext(c)
	logger.Debug("handling login end request")

	values := requestURL.Query()
	code := values.Get("code")
	state := values.Get("state")
	queryErr := values.Get("error")

	failed := state != "" && queryErr != ""

	if failed {
		logger.Debug("login failed")
		var status int
		if queryErr == "login_required" {
			status = http.StatusUnauthorized
		} else {
			status = http.StatusBadRequest
		}
		c.AbortWithStatus(status)
		return
	}

	handleAuth := state != "" && code != ""

	loggedIn := false
	if handleAuth {
		logger.Debug("login success")
		originalState, err := c.Cookie("state")
		if err != nil {
			logger.With(
				"error", err,
			).Debug("unable to access state cookie")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.SetCookie("state", "", -1, "/", "", c.Request.URL.Scheme == "https", true)
		if state != originalState {
			logger.With(
				"error", err,
			).Debug("state does not match")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		nonce, err := c.Cookie("nonce")
		if err != nil {
			logger.With(
				"error", err,
			).Debug("unable to get nonce cookie")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.SetCookie("nonce", "", -1, "/", "", c.Request.URL.Scheme == "https", true)

		oauth2Token, err := o.oauthConfig.Exchange(ctx, code)
		if err != nil {
			logger.With(
				"error", err,
			).Debug("unable to exchange token")
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		var ok bool
		rawIDToken, ok = oauth2Token.Extra("id_token").(string)
		if !ok {
			logger.With(
				"ok", ok,
			).Debug("unable to get id_token")
			_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("no id_token field in oauth2 token"))
			return
		}

		idToken, err := o.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			logger.With(
				"error", err,
			).Debug("unable to verify id_token")
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		if idToken.Nonce != nonce {
			logger.Debug("nonce does not match")
			_ = c.AbortWithError(http.StatusBadRequest, fmt.Errorf("nonce did not match"))
			return
		}

		session := ginsession.FromContext(c)
		tokenString, err := tokenToJSONString(oauth2Token)
		if err != nil {
			logger.Debug("can't convert token to string")
			_ = c.AbortWithError(http.StatusBadRequest, fmt.Errorf("can't convert token to string"))
			return
		}
		session.Set(TokenKey, tokenString)
		session.Set(IDTokenKey, rawIDToken)
		if err := session.Save(); err != nil {
			logger.With("error", err,
				"id_token_size", len(rawIDToken)).Debug("can't save session storage")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		logger.With("session_id", session.SessionID()).Debug("user is logged in")
		loggedIn = true

		// extract the access_token and refresh_token from the oauth2Token
		// to be returned in the response for the web auth token lifecycle.
		accessToken = oauth2Token.Extra("access_token").(string)
		refreshToken = oauth2Token.Extra("refresh_token").(string)
	} else {
		logger.Debug("checking if user is logged in")
		loggedIn = isLoggedIn(c)
	}

	session := ginsession.FromContext(c)
	logger.With("session_id", session.SessionID()).With("logged_in", loggedIn).Debug("complete")
	res := models.LoginEndResponse{
		Handled:      handleAuth,
		LoggedIn:     loggedIn,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	c.JSON(http.StatusOK, res)
}

// UserInfo retrieves details about the currently authenticated user.
// @Summary     Retrieve Current User Information
// @Description Fetches and returns information for the user who is currently authenticated.
// @Id          UserInfo
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Success     200 {object} models.UserInfoResponse
// @Router      /web/user_info [get]
func (o *OidcAgent) UserInfo(c *gin.Context) {
	session := ginsession.FromContext(c)
	ctx := o.prepareContext(c)
	tokenRaw, ok := session.Get(TokenKey)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	token, err := JsonStringToToken(tokenRaw.(string))
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	src := o.oauthConfig.TokenSource(ctx, token)

	info, err := o.provider.UserInfo(ctx, src)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	var claims struct {
		EmailVerified bool   `json:"email_verified"`
		Email         string `json:"email"`
		Username      string `json:"preferred_username"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		UpdatedAt     int64  `json:"updated_at"`
	}

	err = info.Claims(&claims)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	o.logger.With("claims", claims).Debug("got claims from id_token")
	res := models.UserInfoResponse{
		Subject:           info.Subject,
		PreferredUsername: claims.Username,
		GivenName:         claims.GivenName,
		UpdatedAt:         int64(claims.UpdatedAt),
		FamilyName:        claims.FamilyName,
		Picture:           claims.Picture,
		EmailVerified:     claims.EmailVerified,
		Email:             claims.Email,
	}

	c.JSON(http.StatusOK, res)
}

// Claims fetches the claims associated with the user's access token.
// @Summary     Get Access Token Claims
// @Description Retrieves the claims present in the user's access token.
// @Id          Claims
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Success     200 {object} map[string]interface{}
// @Router      /web/claims [get]
func (o *OidcAgent) Claims(c *gin.Context) {
	session := ginsession.FromContext(c)
	ctx := o.prepareContext(c)
	idTokenRaw, ok := session.Get(IDTokenKey)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	idToken, err := o.verifier.Verify(ctx, idTokenRaw.(string))
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	var claims map[string]interface{}
	err = idToken.Claims(claims)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, claims)
}

// Refresh updates the user's access token.
// @Summary     Refresh Access Token
// @Description Obtains and updates a new access token for the user.
// @Id          Refresh
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Param        data body models.RefreshTokenRequest true "End Login"
// @Success      200 {object} models.RefreshTokenResponse
// @Router      /web/refresh [post]
func (o *OidcAgent) Refresh(c *gin.Context) {
	logger := o.logger

	var data models.RefreshTokenRequest

	if err := c.BindJSON(&data); err != nil {
		logger.Debugf("Failed to bind JSON: %v", err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	session := ginsession.FromContext(c)
	ctx := o.prepareContext(c)

	// Attempt to get the session token
	tokenRaw, ok := session.Get(TokenKey)
	if !ok && data.RefreshToken == "" {
		logger.Debug("No token in session and no refresh token provided, unauthorized")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var newToken *oauth2.Token
	var err error

	if ok {
		// If session token is available, use it
		token, err := JsonStringToToken(tokenRaw.(string))
		if err != nil {
			logger.Debugf("Failed to convert token from JSON string: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		src := o.oauthConfig.TokenSource(ctx, token)
		newToken, err = src.Token()
		if err != nil {
			logger.Debugf("Failed to refresh token with session token: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	} else {
		// If no session token, use the refresh token provided in the request
		t := &oauth2.Token{RefreshToken: data.RefreshToken}
		src := o.oauthConfig.TokenSource(ctx, t)
		newToken, err = src.Token()
		if err != nil {
			logger.Debugf("Failed to refresh token with provided refresh token: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	tokenString, err := tokenToJSONString(newToken)
	if err != nil {
		logger.Debugf("Failed to convert new token to string: %v", err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Update the session with the new token
	session.Set(TokenKey, tokenString)
	if err :=
		session.Save(); err != nil {
		logger.Debugf("Failed to save new token in session: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Send the refreshed token in the response
	c.JSON(http.StatusOK, models.RefreshTokenResponse{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
	})
}

// Logout provides the URL to log out the current user.
// @Summary     Generate Logout URL
// @Description Provides the URL to initiate the logout process for the current user.
// @Id          Logout
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Success     200 {object} models.LogoutResponse
// @Router      /web/logout [post]
func (o *OidcAgent) Logout(c *gin.Context) {
	session := ginsession.FromContext(c)

	idToken, ok := session.Get(IDTokenKey)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	session.Delete(IDTokenKey)
	session.Delete(TokenKey)
	if err := session.Save(); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	logoutURL, err := o.LogoutURL(idToken.(string))
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, models.LogoutResponse{
		LogoutURL: logoutURL.String(),
	})
}

func (o *OidcAgent) CodeFlowProxy(c *gin.Context) {
	session := ginsession.FromContext(c)
	ctx := o.prepareContext(c)
	tokenRaw, ok := session.Get(TokenKey)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	token, err := JsonStringToToken(tokenRaw.(string))
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	// Use a static token source to avoid automatically
	// refreshing the token - this needs to be handled
	// by the frontend
	src := oauth2.StaticTokenSource(token)
	client := oauth2.NewClient(ctx, src)
	proxy := httputil.NewSingleHostReverseProxy(o.backend)

	// Use the client transport
	proxy.Transport = client.Transport
	proxy.Director = func(req *http.Request) {
		req.Header = c.Request.Header
		req.Host = o.backend.Host
		req.URL.Scheme = o.backend.Scheme
		req.URL.Host = o.backend.Host
		req.URL.Path = c.Param("proxyPath")
	}
	proxy.ServeHTTP(c.Writer, c.Request)
}

func isLoggedIn(c *gin.Context) bool {
	session := ginsession.FromContext(c)
	_, ok := session.Get(TokenKey)
	return ok
}

// CheckAuth checks if the user is authenticated.
// @Summary     Check Authentication
// @Description Checks if the user is currently authenticated
// @Id          CheckAuth
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Success     200 {object} map[string]bool "logged_in status will be returned"
// @Router      /check/auth [get]
func (o *OidcAgent) CheckAuth(c *gin.Context) {
	loggedIn := isLoggedIn(c)
	c.JSON(http.StatusOK, gin.H{"logged_in": loggedIn})
}

// DeviceStart initiates the device login process.
// @Summary     Start Login
// @Description Starts a device login request
// @Id          DeviceStart
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Success     200 {object} models.DeviceStartResponse
// @Router      /device/login/start [post]
func (o *OidcAgent) DeviceStart(c *gin.Context) {
	now := time.Now()
	c.JSON(http.StatusOK, models.DeviceStartResponse{
		DeviceAuthURL: o.deviceAuthURL,
		Issuer:        o.oidcIssuer,
		ClientID:      o.clientID,
		ServerTime:    &now,
	})
}

func (o *OidcAgent) DeviceFlowProxy(c *gin.Context) {
	proxy := httputil.NewSingleHostReverseProxy(o.backend)
	proxy.Director = func(req *http.Request) {
		req.Header = c.Request.Header
		req.Host = o.backend.Host
		req.URL.Scheme = o.backend.Scheme
		req.URL.Host = o.backend.Host
		req.URL.Path = c.Param("proxyPath")
	}
	proxy.ServeHTTP(c.Writer, c.Request)
}

func tokenToJSONString(t *oauth2.Token) (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func JsonStringToToken(s string) (*oauth2.Token, error) {
	var t oauth2.Token
	if err := json.Unmarshal([]byte(s), &t); err != nil {
		return nil, err
	}
	return &t, nil

}
