/**
 * Copyright 2021 - Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	idx "github.com/okta/okta-idx-golang"
	"github.com/patrickmn/go-cache"

	"github.com/okta/samples-golang/identity-engine/embedded-sign-in-widget/config"
)

const (
	SESSION_STORE_NAME = "okta-self-hosted-session-store"
)

// Internal Struct around the Server to use with the sample app.
//Powers the UX and templates from the data in this struct.
type Server struct {
	config       *config.Config
	idxClient    *idx.Client
	tpl          *template.Template
	sessionStore *sessions.CookieStore
	LoginData    LoginData
	svc          *http.Server
	address      string
	cache        *cache.Cache
}

// Utilized to store meta data that is also used to drive the app UX templates
type LoginData struct {
	IsAuthenticated     bool
	BaseUrl             string
	ClientId            string
	RedirectURI         string
	Issuer              string
	State               string
	InteractionHandle   string
	CodeChallenge       string
	CodeChallengeMethod string
	OTP                 string
	Lang                string
}

// Entry point into the server.go from main.go
// All the template files are set up and init method basically
func NewServer(c *config.Config) *Server {
	idx, err := idx.NewClient()
	if err != nil {
		log.Fatalf("new client error: %+v", err)
	}

	return &Server{
		config:       c,
		tpl:          template.Must(template.ParseGlob("templates/*.gohtml")),
		idxClient:    idx,
		sessionStore: sessions.NewCookieStore([]byte("randomKey")),
		cache:        cache.New(5*time.Minute, 10*time.Minute),
	}
}

//Getter for the address eg. port = 8000
func (s *Server) Address() string {
	return s.address
}

func (s *Server) Run() {
	r := mux.NewRouter()
	r.Use(s.loggingMiddleware)

	r.HandleFunc("/", s.HomeHandler).Methods("GET")

	r.HandleFunc("/login", s.LoginHandler).Methods("GET")
	r.HandleFunc("/login/callback", s.LoginCallbackHandler).Methods("GET")
	r.HandleFunc("/profile", s.ProfileHandler).Methods("GET")
	r.HandleFunc("/logout", s.LogoutHandler).Methods("POST")
	r.HandleFunc("/logout", s.LogoutHandler).Methods("GET")
	r.HandleFunc("/issues", s.IssueHandler).Methods("GET")
	r.HandleFunc("/contact", s.ContactHandler).Methods("GET")
	r.HandleFunc("/terms", s.TCHandler).Methods("GET")
	r.HandleFunc("/tenant", s.TenantHandler).Methods("GET")
	r.HandleFunc("/docs", s.DocHandler).Methods("GET")

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./templates/static/"))))

	addr := "localhost:8000"
	logger := log.New(os.Stderr, "http: ", log.LstdFlags)
	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		ErrorLog:     logger,
	}

	s.svc = srv
	s.address = srv.Addr

	log.Printf("running sample on addr %q\n", addr)

	if !s.config.Testing {
		log.Fatal(srv.ListenAndServe())
	} else {
		go func() {
			log.Fatal(srv.ListenAndServe())
		}()
	}
}
func (s *Server) IssueHandler(w http.ResponseWriter, r *http.Request) {
	//local struct to have profile data and work with the UX
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}

	s.tpl.ExecuteTemplate(w, "issues.gohtml", data)
}
func (s *Server) DocHandler(w http.ResponseWriter, r *http.Request) {
	//local struct to have profile data and work with the UX
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}

	s.tpl.ExecuteTemplate(w, "docs.gohtml", data)
}

func (s *Server) ContactHandler(w http.ResponseWriter, r *http.Request) {
	//local struct to have profile data and work with the UX
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}

	s.tpl.ExecuteTemplate(w, "contact.gohtml", data)
}

func (s *Server) TenantHandler(w http.ResponseWriter, r *http.Request) {
	//local struct to have profile data and work with the UX
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}

	s.tpl.ExecuteTemplate(w, "tenant.gohtml", data)
}

func (s *Server) TCHandler(w http.ResponseWriter, r *http.Request) {
	//local struct to have profile data and work with the UX
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}

	s.tpl.ExecuteTemplate(w, "terms.gohtml", data)
}

func (s *Server) HomeHandler(w http.ResponseWriter, r *http.Request) {
	//local struct to have profile data and work with the UX
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}

	s.tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	//API call to get interact + introspec endpoint on IDX
	// Login Response
	lr, err := s.idxClient.InitLogin(r.Context())
	if err != nil {
		log.Fatalf("error idx client init login: %+v", err)
	}
	s.cache.Set("loginResponse", lr, time.Minute*5)

	keys, ok := r.URL.Query()["lang"]
	key := "en" // set this as default

	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'lang' is missing")
	} else {
		// Query()["key"] will return an array of items,
		// we only want the single item.
		key = keys[0]
		log.Println("Url Param 'key' is: " + string(key))
	}

	issuerURL := s.idxClient.Config().Okta.IDX.Issuer
	issuerParts, err := url.Parse(issuerURL)
	if err != nil {
		log.Fatalf("error: %s\n", err.Error())
	}
	baseUrl := issuerParts.Scheme + "://" + issuerParts.Hostname()
	//set up our datastructure with all the config details and the interact handle with bootstrapping the widget.
	s.LoginData = LoginData{
		IsAuthenticated:     lr.IsAuthenticated(),
		BaseUrl:             baseUrl,
		RedirectURI:         s.idxClient.Config().Okta.IDX.RedirectURI,
		ClientId:            s.idxClient.Config().Okta.IDX.ClientID,
		Issuer:              s.idxClient.Config().Okta.IDX.Issuer,
		State:               lr.Context().State,
		CodeChallenge:       lr.Context().CodeChallenge,
		CodeChallengeMethod: lr.Context().CodeChallengeMethod,
		InteractionHandle:   lr.Context().InteractionHandle.InteractionHandle,
		Lang:                key,
	}
	err = s.tpl.ExecuteTemplate(w, "login.gohtml", s.LoginData)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
	}
}

func (s *Server) LoginCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check if interaction_required error is returned
	if r.URL.Query().Get("error") == "interaction_required" {
		w.Header().Add("Cache-Control", "no-cache")

		s.LoginData.IsAuthenticated = s.isAuthenticated(r)
		err := s.tpl.ExecuteTemplate(w, "login.gohtml", s.LoginData)
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
		return
	}

	clr, found := s.cache.Get("loginResponse")
	if !found {
		log.Fatalln("loginResponse is not cached")
	}
	//once again populate lr for this handler from the cache.
	lr := clr.(*idx.LoginResponse)
	lr, err := lr.WhereAmI(r.Context())
	if !found {
		log.Fatalf("loginRespons WhereAmI error: %s", err.Error())
	}

	// Check the state that was returned in the query string is the same as the above state
	// Match if the state token from the handler matches the one we got from lr before asking for id token
	if r.URL.Query().Get("state") != lr.Context().State {
		fmt.Fprintf(w, "The state was not as expected, got %q, expected %q", r.URL.Query().Get("state"), lr.Context().State)
		return
	}

	// inbound magic link otp. TBD why is the otp in the request? Polling here to get the otp from the client side.
	if r.URL.Query().Get("otp") != "" {
		w.Header().Add("Cache-Control", "no-cache")

		s.LoginData.OTP = r.URL.Query().Get("otp")
		err := s.tpl.ExecuteTemplate(w, "login.gohtml", s.LoginData)
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
		return
	}

	// Check that the interaction_code was provided
	if r.URL.Query().Get("interaction_code") == "" {
		fmt.Fprintln(w, "The interaction_code was not returned or is not accessible")
		return
	}

	//destination for the id and access token.
	session, err := s.sessionStore.Get(r, SESSION_STORE_NAME)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	//magic of getting everything like interaction code, and 1.request context (why) 2.lr has all our data.
	// Exchange it for tokens.
	accessToken, err := s.idxClient.RedeemInteractionCode(r.Context(), lr.Context(), r.URL.Query().Get("interaction_code"))
	if err != nil {
		log.Fatalf("access token error: %+v\n", err)
	}
	session.Values["id_token"] = accessToken.IDToken
	session.Values["access_token"] = accessToken.AccessToken
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}
	s.tpl.ExecuteTemplate(w, "profile.gohtml", data)
}

func (s *Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// revoke the oauth2 access token it exists in the session API side before deleting session info
	logoutURL := "/"
	if session, err := s.sessionStore.Get(r, SESSION_STORE_NAME); err == nil {
		if accessToken, found := session.Values["access_token"]; found {
			if err := s.idxClient.RevokeToken(r.Context(), accessToken.(string)); err != nil {
				fmt.Printf("revoke error: %+v\n", err)
			}
		}

		if idToken, found := session.Values["id_token"]; found {
			// redirect must match one of the "Sign-out redirect URIs" defined on the Okta application
			redirect, _ := url.Parse(s.idxClient.Config().Okta.IDX.RedirectURI)
			redirect.Path = "/"
			params := url.Values{
				"id_token_hint":            {idToken.(string)},
				"post_logout_redirect_uri": {redirect.String()},
			}
			// server must redirect out to the Okta API to perform a proper logout
			logoutURL = s.oAuthEndPoint(fmt.Sprintf("logout?%s", params.Encode()))
		}

		delete(session.Values, "id_token")
		delete(session.Values, "access_token")
		session.Save(r, w)
	}

	// reset the idx context
	s.cache.Flush()
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DEBUG") == "true" || !s.config.Testing {
			log.Printf("%s: %s\n", r.Method, r.RequestURI)
		}
		next.ServeHTTP(w, r)
	})
}

// the helper that populates profile data
func (s *Server) getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string) // map key value pair

	session, _ := s.sessionStore.Get(r, SESSION_STORE_NAME)
	if accessToken, found := session.Values["access_token"]; found {
		reqUrl := s.oAuthEndPoint("userinfo") // the endpoint which is to be called for profile data
		req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
		h := req.Header
		h.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		h.Add("Accept", "application/json")

		client := &http.Client{Timeout: time.Second * 30}
		resp, _ := client.Do(req)
		body, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		json.Unmarshal(body, &m)
	}

	return m
}

//Checks if id token is in it or not and returns true/false
func (s *Server) isAuthenticated(r *http.Request) bool {
	session, _ := s.sessionStore.Get(r, SESSION_STORE_NAME)
	_, found := session.Values["id_token"]
	return found
}

func (s *Server) oAuthEndPoint(operation string) string {
	var endPoint string
	issuer := s.idxClient.Config().Okta.IDX.Issuer
	if strings.Contains(issuer, "oauth2") {
		endPoint = fmt.Sprintf("%s/v1/%s", issuer, operation)
	} else {
		endPoint = fmt.Sprintf("%s/oauth2/v1/%s", issuer, operation)
	}
	return endPoint
}
