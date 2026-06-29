package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type notificationResponse struct {
	ID                   string                  `json:"id"`
	TenantID             string                  `json:"tenant_id"`
	Destination          string                  `json:"destination"`
	Kind                 string                  `json:"kind,omitempty"`
	CertificateID        string                  `json:"certificate_id,omitempty"`
	Subject              string                  `json:"subject,omitempty"`
	Serial               string                  `json:"serial,omitempty"`
	NotAfter             *time.Time              `json:"not_after,omitempty"`
	Detail               string                  `json:"detail,omitempty"`
	Severity             string                  `json:"severity,omitempty"`
	RoutingPolicyID      string                  `json:"routing_policy_id,omitempty"`
	ThresholdDays        *int                    `json:"threshold_days,omitempty"`
	OwnerID              string                  `json:"owner_id,omitempty"`
	OwnerName            string                  `json:"owner_name,omitempty"`
	OwnerEmail           string                  `json:"owner_email,omitempty"`
	EscalationRecipients []notify.AlertRecipient `json:"escalation_recipients,omitempty"`
	Status               string                  `json:"status"`
	Attempts             int                     `json:"attempts"`
	LastError            string                  `json:"last_error,omitempty"`
	IdempotencyKey       string                  `json:"idempotency_key,omitempty"`
	CreatedAt            time.Time               `json:"created_at"`
	DeliveredAt          *time.Time              `json:"delivered_at,omitempty"`
	ReadAt               *time.Time              `json:"read_at,omitempty"`
}

type notificationChannelResponse struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	Configured  bool   `json:"configured"`
	Delivery    string `json:"delivery"`
	Description string `json:"description"`
}

type notificationChannelList struct {
	Items []notificationChannelResponse `json:"items"`
}

func (a *API) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, notificationChannelList{Items: notificationChannelCatalog(a.notificationChannels)})
}

func (a *API) listNotifications(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured"))
		return
	}
	limit, after, status, err := notificationPageParams(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	rows, err := a.store.ListNotificationOutboxPage(r.Context(), tenantID, after, limit, status)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]notificationResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toNotificationResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeNotificationCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getNotification(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured"))
		return
	}
	id, err := notificationPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	row, err := a.store.GetNotificationOutbox(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toNotificationResponse(row))
}

//trstctl:mutation
func (a *API) markNotificationRead(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id, err := notificationPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil || a.log == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured")
		}
		if _, err := a.store.GetNotificationOutbox(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		readAt := time.Now().UTC()
		payload, err := json.Marshal(projections.NotificationRead{OutboxID: id, ReadAt: readAt})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{
			Type:     projections.EventNotificationRead,
			TenantID: tenantID,
			Data:     payload,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.store).Apply(ctx, ev); err != nil {
			return 0, nil, err
		}
		row, err := a.store.GetNotificationOutbox(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toNotificationResponse(row), nil
	})
}

//trstctl:mutation
func (a *API) requeueNotification(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id, err := notificationPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured")
		}
		row, err := a.store.RequeueNotificationOutbox(ctx, tenantID, id)
		if err != nil {
			if errors.Is(err, store.ErrNotificationAlreadyProcessing) || errors.Is(err, store.ErrNotificationNotDead) {
				return 0, nil, errStatus(http.StatusConflict, err.Error())
			}
			return 0, nil, err
		}
		return http.StatusOK, toNotificationResponse(row), nil
	})
}

func notificationPageParams(r *http.Request) (limit int, after int64, status string, err error) {
	limit, err = pageLimit(r)
	if err != nil {
		return 0, 0, "", errStatus(http.StatusBadRequest, err.Error())
	}
	if c := r.URL.Query().Get("cursor"); c != "" {
		after, err = decodeNotificationCursor(c)
		if err != nil {
			return 0, 0, "", errStatus(http.StatusBadRequest, "invalid cursor")
		}
	}
	status, err = parseNotificationStatus(r.URL.Query().Get("status"))
	if err != nil {
		return 0, 0, "", err
	}
	return limit, after, status, nil
}

func parseNotificationStatus(raw string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case "", "pending", "sent", "dead", "read":
		return status, nil
	default:
		return "", errStatus(http.StatusBadRequest, "status must be pending, sent, dead, or read")
	}
}

func notificationPathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		return 0, errStatus(http.StatusBadRequest, "notification id must be a positive integer")
	}
	return id, nil
}

func encodeNotificationCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

func decodeNotificationCursor(cursor string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || id < 0 {
		return 0, errors.New("invalid notification cursor")
	}
	return id, nil
}

func toNotificationResponse(row store.NotificationOutboxRecord) notificationResponse {
	var alert notify.Alert
	_ = json.Unmarshal(row.Payload, &alert)
	var notAfter *time.Time
	if !alert.NotAfter.IsZero() {
		t := alert.NotAfter
		notAfter = &t
	}
	return notificationResponse{
		ID:                   strconv.FormatInt(row.ID, 10),
		TenantID:             row.TenantID,
		Destination:          row.Destination,
		Kind:                 alert.Kind,
		CertificateID:        alert.CertificateID,
		Subject:              alert.Subject,
		Serial:               alert.Serial,
		NotAfter:             notAfter,
		Detail:               alert.Detail,
		Severity:             alert.Severity,
		RoutingPolicyID:      alert.RoutingPolicyID,
		ThresholdDays:        alert.ThresholdDays,
		OwnerID:              alert.OwnerID,
		OwnerName:            alert.OwnerName,
		OwnerEmail:           alert.OwnerEmail,
		EscalationRecipients: append([]notify.AlertRecipient(nil), alert.EscalationRecipients...),
		Status:               row.Status,
		Attempts:             row.Attempts,
		LastError:            row.LastError,
		IdempotencyKey:       row.IdempotencyKey,
		CreatedAt:            row.CreatedAt,
		DeliveredAt:          row.DeliveredAt,
		ReadAt:               row.ReadAt,
	}
}

func notificationChannelCatalog(configured []string) []notificationChannelResponse {
	configuredSet := make(map[string]bool, len(configured))
	for _, name := range configured {
		id := canonicalNotificationChannelID(name)
		if id != "" {
			configuredSet[id] = true
		}
	}
	base := []notificationChannelResponse{
		{ID: "email", Label: "Email", Category: "smtp", Description: "SMTP email alert delivery"},
		{ID: "slack", Label: "Slack", Category: "chat", Description: "Slack incoming-webhook alert delivery"},
		{ID: "msteams", Label: "Microsoft Teams", Category: "chat", Description: "Microsoft Teams incoming-webhook alert delivery"},
		{ID: "sms", Label: "SMS", Category: "mobile", Description: "SMS gateway alert delivery"},
		{ID: "siem", Label: "SIEM", Category: "security", Description: "Security-event collector alert delivery"},
		{ID: "pagerduty", Label: "PagerDuty", Category: "incident", Description: "PagerDuty Events API alert delivery"},
		{ID: "opsgenie", Label: "OpsGenie", Category: "incident", Description: "OpsGenie alert delivery"},
		{ID: "webhook", Label: "Webhook", Category: "webhook", Description: "Generic HMAC-signed webhook alert delivery"},
	}
	seen := make(map[string]bool, len(base))
	for i := range base {
		base[i].Configured = configuredSet[base[i].ID]
		base[i].Delivery = "notification.* outbox fanout"
		seen[base[i].ID] = true
	}
	for _, name := range configured {
		id := canonicalNotificationChannelID(name)
		if id == "" || seen[id] {
			continue
		}
		base = append(base, notificationChannelResponse{
			ID: id, Label: id, Category: "custom", Configured: true,
			Delivery: "notification.* outbox fanout", Description: "Custom registered notification sink",
		})
		seen[id] = true
	}
	return base
}

func canonicalNotificationChannelID(name string) string {
	id := strings.ToLower(strings.TrimSpace(name))
	compact := strings.NewReplacer(" ", "", "-", "", "_", "").Replace(id)
	switch compact {
	case "teams", "microsoftteams", "msftteams", "msteams":
		return "msteams"
	default:
		return id
	}
}
