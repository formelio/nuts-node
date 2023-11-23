// Package client provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.0.0 DO NOT EDIT.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/oapi-codegen/runtime"
)

// AuthorizedRequest The request contains all params involved with the request.
// It might be the case that the caller mapped credential fields to additional params.
type AuthorizedRequest struct {
	// Audience The audience of the access token. This is the identifier (DID) of the authorizer and issuer of the access token.
	Audience string `json:"audience"`

	// ClientId The client ID of the client that requested the resource (DID).
	ClientId string `json:"client_id"`

	// PresentationSubmission A presentation submission is a JSON object that maps requirements from the Presentation Definition to the verifiable presentations that were used to request an access token.
	// Specified at https://identity.foundation/presentation-exchange/spec/v2.0.0/
	// A JSON schema is available at https://identity.foundation/presentation-exchange/#json-schema
	PresentationSubmission PresentationSubmission `json:"presentation_submission"`

	// RequestMethod The method of the resource request.
	RequestMethod string `json:"request_method"`

	// RequestUrl The URL of the resource request.
	RequestUrl string `json:"request_url"`

	// Scope The scope used in the authorization request.
	Scope string `json:"scope"`

	// Vps The verifiable presentations that were used to request the access token.
	// The verifiable presentations could be in JWT format or in JSON format.
	Vps []interface{} `json:"vps"`
}

// AuthorizedResponse The response indicates if the access token grants access to the requested resource.
// If the access token grants access, the response will be 200 with a boolean value set to true.
// If the access token does not grant access, the response will be 200 with a boolean value set to false.
type AuthorizedResponse struct {
	// Authorized Indicates if the access token grants access to the requested resource.
	Authorized bool `json:"authorized"`
}

// PresentationDefinitionParams defines parameters for PresentationDefinition.
type PresentationDefinitionParams struct {
	// Authorizer URLEncoded DID.
	Authorizer string `form:"authorizer" json:"authorizer"`

	// Scope This is the scope used in the OpenID4VP authorization request.
	// It is a space separated list of scopes.
	Scope string `form:"scope" json:"scope"`
}

// CheckAuthorizedJSONRequestBody defines body for CheckAuthorized for application/json ContentType.
type CheckAuthorizedJSONRequestBody = AuthorizedRequest

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// CheckAuthorizedWithBody request with any body
	CheckAuthorizedWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	CheckAuthorized(ctx context.Context, body CheckAuthorizedJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PresentationDefinition request
	PresentationDefinition(ctx context.Context, params *PresentationDefinitionParams, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) CheckAuthorizedWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCheckAuthorizedRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) CheckAuthorized(ctx context.Context, body CheckAuthorizedJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCheckAuthorizedRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PresentationDefinition(ctx context.Context, params *PresentationDefinitionParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPresentationDefinitionRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewCheckAuthorizedRequest calls the generic CheckAuthorized builder with application/json body
func NewCheckAuthorizedRequest(server string, body CheckAuthorizedJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewCheckAuthorizedRequestWithBody(server, "application/json", bodyReader)
}

// NewCheckAuthorizedRequestWithBody generates requests for CheckAuthorized with any type of body
func NewCheckAuthorizedRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/authorized")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewPresentationDefinitionRequest generates requests for PresentationDefinition
func NewPresentationDefinitionRequest(server string, params *PresentationDefinitionParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/presentation_definition")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "authorizer", runtime.ParamLocationQuery, params.Authorizer); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "scope", runtime.ParamLocationQuery, params.Scope); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// CheckAuthorizedWithBodyWithResponse request with any body
	CheckAuthorizedWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CheckAuthorizedResponse, error)

	CheckAuthorizedWithResponse(ctx context.Context, body CheckAuthorizedJSONRequestBody, reqEditors ...RequestEditorFn) (*CheckAuthorizedResponse, error)

	// PresentationDefinitionWithResponse request
	PresentationDefinitionWithResponse(ctx context.Context, params *PresentationDefinitionParams, reqEditors ...RequestEditorFn) (*PresentationDefinitionResponse, error)
}

type CheckAuthorizedResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *AuthorizedResponse
}

// Status returns HTTPResponse.Status
func (r CheckAuthorizedResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r CheckAuthorizedResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PresentationDefinitionResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *PresentationDefinition
}

// Status returns HTTPResponse.Status
func (r PresentationDefinitionResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PresentationDefinitionResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// CheckAuthorizedWithBodyWithResponse request with arbitrary body returning *CheckAuthorizedResponse
func (c *ClientWithResponses) CheckAuthorizedWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CheckAuthorizedResponse, error) {
	rsp, err := c.CheckAuthorizedWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCheckAuthorizedResponse(rsp)
}

func (c *ClientWithResponses) CheckAuthorizedWithResponse(ctx context.Context, body CheckAuthorizedJSONRequestBody, reqEditors ...RequestEditorFn) (*CheckAuthorizedResponse, error) {
	rsp, err := c.CheckAuthorized(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCheckAuthorizedResponse(rsp)
}

// PresentationDefinitionWithResponse request returning *PresentationDefinitionResponse
func (c *ClientWithResponses) PresentationDefinitionWithResponse(ctx context.Context, params *PresentationDefinitionParams, reqEditors ...RequestEditorFn) (*PresentationDefinitionResponse, error) {
	rsp, err := c.PresentationDefinition(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePresentationDefinitionResponse(rsp)
}

// ParseCheckAuthorizedResponse parses an HTTP response from a CheckAuthorizedWithResponse call
func ParseCheckAuthorizedResponse(rsp *http.Response) (*CheckAuthorizedResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &CheckAuthorizedResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest AuthorizedResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParsePresentationDefinitionResponse parses an HTTP response from a PresentationDefinitionWithResponse call
func ParsePresentationDefinitionResponse(rsp *http.Response) (*PresentationDefinitionResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &PresentationDefinitionResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest PresentationDefinition
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}
