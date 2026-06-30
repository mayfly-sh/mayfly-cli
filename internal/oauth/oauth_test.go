package oauth

import (
	"context"
	"testing"
	"time"
)

type stubProvider struct{ id string }

func (s stubProvider) Metadata() Metadata {
	return Metadata{ID: s.id, DisplayName: s.id, Kind: KindOAuth2Device}
}
func (s stubProvider) StartDeviceAuthorization(context.Context) (*DeviceAuthorization, error) {
	return &DeviceAuthorization{DeviceCode: "dc", Interval: 0}, nil
}
func (s stubProvider) PollToken(context.Context, string) (*PollResult, error) {
	return &PollResult{State: PollApproved, Token: &Token{AccessToken: "tok"}}, nil
}
func (s stubProvider) FetchIdentity(context.Context, *Token) (*Identity, error) {
	return &Identity{Provider: s.id, Subject: "1", Username: "u"}, nil
}

func TestRegistryRegisterGetList(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubProvider{id: "github"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(stubProvider{id: "keycloak"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(stubProvider{id: "github"}); err == nil {
		t.Error("expected duplicate registration to error")
	}
	if err := r.Register(stubProvider{id: ""}); err == nil {
		t.Error("expected empty id to error")
	}

	if _, ok := r.Get("github"); !ok {
		t.Error("github should be present")
	}
	if _, ok := r.Get("missing"); ok {
		t.Error("missing should be absent")
	}

	list := r.List()
	if len(list) != 2 || list[0].ID != "github" || list[1].ID != "keycloak" {
		t.Errorf("List not sorted/complete: %+v", list)
	}
}

func TestSessionIntervalDefault(t *testing.T) {
	s, err := StartSession(context.Background(), stubProvider{id: "github"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Interval() != 5*time.Second {
		t.Errorf("interval = %v, want 5s default", s.Interval())
	}
}

func TestTokenExpired(t *testing.T) {
	if (&Token{}).Expired() {
		t.Error("zero expiry should be treated as not expired")
	}
	if !(&Token{Expiry: time.Now().Add(-time.Minute)}).Expired() {
		t.Error("past expiry should be expired")
	}
	if (&Token{Expiry: time.Now().Add(time.Hour)}).Expired() {
		t.Error("future expiry should not be expired")
	}
}
