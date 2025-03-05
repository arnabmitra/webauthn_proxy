package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

// Get "username" query param and validate against supplied regex
func GetUsername(r *http.Request, regex string) (string, error) {
	username := r.URL.Query().Get("username")
	if username == "" {
		return "", fmt.Errorf("you must supply a username")
	}
	if matched, err := regexp.MatchString(regex, username); !matched || err != nil {
		return "", fmt.Errorf("you must supply a valid username")
	}
	return username, nil
}

// Marshal object to JSON and write response
func JSONResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

// Fetch webauthn session data from session store
func FetchWebauthnSession(session *sessions.Session, key string, r *http.Request) (webauthn.SessionData, error) {
	sessionData := webauthn.SessionData{}
	assertion, ok := session.Values[key].([]byte)
	if !ok {
		return sessionData, fmt.Errorf("error unmarshaling session data")
	}
	err := json.Unmarshal(assertion, &sessionData)
	if err != nil {
		return sessionData, err
	}
	// Delete the value from the session now that it's been read
	delete(session.Values, key)
	return sessionData, nil
}

// Save webauthn session data to session store
func SaveWebauthnSession(session *sessions.Session, key string, sessionData *webauthn.SessionData, r *http.Request, w http.ResponseWriter) error {
	marshaledData, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}
	session.Values[key] = marshaledData
	session.Save(r, w)
	return nil
}

// ExpireWebauthnSession invalidate session by expiring cookie
func ExpireWebauthnSession(session *sessions.Session, r *http.Request, w http.ResponseWriter) {
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	session.Save(r, w)
}

// GetUserIP return user IP address
func GetUserIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}
	ip = r.Header.Get("X-Real-Ip")
	if ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// Generate crytographically secure challenge
func GenChallenge() string {
	//call on the import DUO method
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		panic("Failed to generate cryptographically secure challenge")
	}
	return base64.RawURLEncoding.EncodeToString(challenge)
}

func PrettyPrint(data interface{}) {
	var p []byte
	p, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s \n", p)
}

// SetupLogging setup logger
func SetupLogging(name, loggingLevel string) *logrus.Entry {
	if loggingLevel != "info" {
		if level, err := logrus.ParseLevel(loggingLevel); err == nil {
			logrus.SetLevel(level)
		}
	}
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: time.RFC3339,
		FullTimestamp:   true,
	})
	// Output to stdout instead of the default stderr.
	logrus.SetOutput(os.Stdout)
	return logrus.WithFields(logrus.Fields{"logger": name})
}

// WebAuthnWrapper wraps the webauthn.WebAuthn type
type WebAuthnWrapper struct {
	*webauthn.WebAuthn
	configvalidated bool
}

// BeginLogin creates the *protocol.CredentialAssertion data payload that should be sent to the user agent for beginning
// the login/assertion process. The format of this data can be seen in §5.5 of the WebAuthn specification. These default
// values can be amended by providing additional LoginOption parameters. This function also returns sessionData, that
// must be stored by the RP in a secure manner and then provided to the FinishLogin function. This data helps us verify
// the ownership of the credential being retrieved.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dictionary-assertion-options)
func (webauthn *WebAuthnWrapper) BeginLogin(user webauthn.User, customChallenge []byte, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	credentials := user.WebAuthnCredentials()

	if len(credentials) == 0 { // If the user does not have any credentials, we cannot perform an assertion.
		return nil, nil, protocol.ErrBadRequest.WithDetails("Found no credentials for user")
	}

	var allowedCredentials = make([]protocol.CredentialDescriptor, len(credentials))

	for i, credential := range credentials {
		allowedCredentials[i] = credential.Descriptor()
	}

	return webauthn.beginLogin(user.WebAuthnID(), allowedCredentials, customChallenge, opts...)
}

func (webauthnWrapper *WebAuthnWrapper) beginLogin(userID []byte, allowedCredentials []protocol.CredentialDescriptor, customChallenge []byte, opts ...webauthn.LoginOption) (assertion *protocol.CredentialAssertion, session *webauthn.SessionData, err error) {

	// config has been validated don't call it again

	var challenge []byte
	if customChallenge != nil {
		challenge = customChallenge
	} else {
		challenge, err = protocol.CreateChallenge()
		if err != nil {
			return nil, nil, err
		}
	}

	if err != nil {
		return nil, nil, err
	}

	assertion = &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge:          challenge,
			RelyingPartyID:     webauthnWrapper.Config.RPID,
			UserVerification:   webauthnWrapper.Config.AuthenticatorSelection.UserVerification,
			AllowedCredentials: allowedCredentials,
		},
	}

	for _, opt := range opts {
		opt(&assertion.Response)
	}

	if assertion.Response.Timeout == 0 {
		switch {
		case assertion.Response.UserVerification == protocol.VerificationDiscouraged:
			assertion.Response.Timeout = int(webauthnWrapper.Config.Timeouts.Login.TimeoutUVD.Milliseconds())
		default:
			assertion.Response.Timeout = int(webauthnWrapper.Config.Timeouts.Login.Timeout.Milliseconds())
		}
	}

	session = &webauthn.SessionData{
		Challenge:            string(challenge),
		UserID:               userID,
		AllowedCredentialIDs: assertion.Response.GetAllowedCredentialIDs(),
		UserVerification:     assertion.Response.UserVerification,
		Extensions:           assertion.Response.Extensions,
	}

	if webauthnWrapper.Config.Timeouts.Login.Enforce {
		session.Expires = time.Now().Add(time.Millisecond * time.Duration(assertion.Response.Timeout))
	}

	return assertion, session, nil
}

// Constants for validation
const (
	errFmtFieldEmpty       = "%s cannot be empty"
	errFmtFieldNotValidURI = "%s is not a valid URI: %v"
	defaultTimeout         = 60000 * time.Millisecond
	defaultTimeoutUVD      = 60000 * time.Millisecond
)

// validateConfig calls the unexported validate method on Config
func (w *WebAuthnWrapper) validateConfig() error {
	config := w.Config
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if w.configvalidated == true {
		return nil
	}

	// Basic validation
	if len(config.RPDisplayName) == 0 {
		return fmt.Errorf(errFmtFieldEmpty, "RPDisplayName")
	}

	if len(config.RPID) == 0 {
		return fmt.Errorf(errFmtFieldEmpty, "RPID")
	}

	// URI validation
	if _, err := url.Parse(config.RPID); err != nil {
		return fmt.Errorf(errFmtFieldNotValidURI, "RPID", err)
	}

	if config.RPIcon != "" {
		if _, err := url.Parse(config.RPIcon); err != nil {
			return fmt.Errorf(errFmtFieldNotValidURI, "RPIcon", err)
		}
	}

	if len(config.RPOrigin) > 0 {
		if len(config.RPOrigins) != 0 {
			return fmt.Errorf("deprecated field 'RPOrigin' can't be defined at the same tme as the replacement field 'RPOrigins'")
		}

		config.RPOrigins = []string{config.RPOrigin}
	}

	if len(config.RPOrigins) == 0 {
		return fmt.Errorf("must provide at least one value to the 'RPOrigins' field")
	}

	if config.AuthenticatorSelection.RequireResidentKey == nil {
		config.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyNotRequired()
	}

	if config.AuthenticatorSelection.UserVerification == "" {
		config.AuthenticatorSelection.UserVerification = protocol.VerificationPreferred
	}

	w.configvalidated = true
	return nil
}
