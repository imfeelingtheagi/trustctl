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

	guuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
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

type notificationRoutingPolicyRequest struct {
	ID                 string              `json:"id,omitempty"`
	Name               string              `json:"name"`
	ChannelsBySeverity map[string][]string `json:"channels_by_severity"`
	DefaultChannels    []string            `json:"default_channels"`
	OwnerRef           string              `json:"owner_ref,omitempty"`
	OwnerEmail         string              `json:"owner_email,omitempty"`
	DigestInterval     int                 `json:"digest_interval_seconds,omitempty"`
	DigestTimezone     string              `json:"digest_timezone,omitempty"`
}

type notificationRoutingPolicyResponse struct {
	ID                 string                            `json:"id"`
	TenantID           string                            `json:"tenant_id"`
	Name               string                            `json:"name"`
	ChannelsBySeverity map[string][]string               `json:"channels_by_severity"`
	DefaultChannels    []string                          `json:"default_channels"`
	OwnerRef           string                            `json:"owner_ref,omitempty"`
	OwnerEmail         string                            `json:"owner_email,omitempty"`
	DigestInterval     int                               `json:"digest_interval_seconds"`
	DigestTimezone     string                            `json:"digest_timezone"`
	DigestPreview      notificationDigestPreviewResponse `json:"digest_preview"`
	CreatedAt          time.Time                         `json:"created_at"`
	UpdatedAt          time.Time                         `json:"updated_at"`
}

type notificationDigestPreviewResponse struct {
	IntervalSeconds int       `json:"interval_seconds"`
	Timezone        string    `json:"timezone"`
	NextRunAt       time.Time `json:"next_run_at"`
}

type notificationChannelTestRequest struct {
	Subject         string `json:"subject,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Detail          string `json:"detail,omitempty"`
	RoutingPolicyID string `json:"routing_policy_id,omitempty"`
	CredentialRef   string `json:"credential_ref,omitempty"`
	OwnerEmail      string `json:"owner_email,omitempty"`
}

type notificationChannelTestResponse struct {
	ChannelID      string    `json:"channel_id"`
	Destination    string    `json:"destination"`
	OutboxID       int64     `json:"outbox_id"`
	Status         string    `json:"status"`
	CredentialRef  string    `json:"credential_ref,omitempty"`
	SecretHandling string    `json:"secret_handling"`
	IdempotencyKey string    `json:"idempotency_key"`
	QueuedAt       time.Time `json:"queued_at"`
}

func (a *API) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, notificationChannelList{Items: notificationChannelCatalog(a.notificationChannels)})
}

func (a *API) listNotificationRoutingPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured"))
		return
	}
	rows, err := a.store.ListNotificationRoutingPolicies(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]notificationRoutingPolicyResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toNotificationRoutingPolicyResponse(row))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) getNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured"))
		return
	}
	id, err := notificationRoutingPolicyPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	row, err := a.store.GetNotificationRoutingPolicy(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toNotificationRoutingPolicyResponse(row))
}

//trstctl:mutation
func (a *API) createNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		policy, err := a.decodeNotificationRoutingPolicyRequest(r, tenantID, "")
		if err != nil {
			return 0, nil, err
		}
		created, err := a.appendNotificationRoutingPolicyUpsert(ctx, tenantID, policy)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toNotificationRoutingPolicyResponse(created), nil
	})
}

//trstctl:mutation
func (a *API) updateNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	pathID, err := notificationRoutingPolicyPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured")
		}
		if _, err := a.store.GetNotificationRoutingPolicy(ctx, tenantID, pathID); err != nil {
			return 0, nil, err
		}
		policy, err := a.decodeNotificationRoutingPolicyRequest(r, tenantID, pathID)
		if err != nil {
			return 0, nil, err
		}
		updated, err := a.appendNotificationRoutingPolicyUpsert(ctx, tenantID, policy)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toNotificationRoutingPolicyResponse(updated), nil
	})
}

//trstctl:mutation
func (a *API) deleteNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id, err := notificationRoutingPolicyPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil || a.log == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured")
		}
		if _, err := a.store.GetNotificationRoutingPolicy(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.NotificationRoutingPolicyDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{
			Type:     projections.EventNotificationRoutingPolicyDeleted,
			TenantID: tenantID,
			Data:     payload,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.store).Apply(ctx, ev); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	channel, err := a.notificationChannelForTest(r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil || a.notificationOutbox == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification test outbox is not configured")
		}
		var req notificationChannelTestRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		severity, err := normalizeNotificationSeverity(req.Severity)
		if err != nil {
			return 0, nil, err
		}
		subject := strings.TrimSpace(req.Subject)
		if subject == "" {
			subject = "Notification channel test"
		}
		detail := strings.TrimSpace(req.Detail)
		if detail == "" {
			detail = "Operator-requested notification channel test"
		}
		routingPolicyID := strings.TrimSpace(req.RoutingPolicyID)
		if routingPolicyID != "" {
			if _, err := guuid.Parse(routingPolicyID); err != nil {
				return 0, nil, errStatus(http.StatusBadRequest, "routing_policy_id must be a UUID")
			}
		}
		alert := notify.Alert{
			Kind:            notify.KindNotificationChannelTest,
			TenantID:        tenantID,
			Subject:         subject,
			Detail:          detail,
			Severity:        severity,
			RoutingPolicyID: routingPolicyID,
			TargetChannel:   channel.ID,
			OwnerEmail:      strings.TrimSpace(req.OwnerEmail),
		}
		payload, err := json.Marshal(alert)
		if err != nil {
			return 0, nil, err
		}
		var (
			outboxID int64
			queuedAt time.Time
		)
		err = a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if _, err := a.notificationOutbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       tenantID,
				Destination:    notify.DestinationTest,
				IdempotencyKey: idempotencyKey,
				Payload:        payload,
			}); err != nil {
				return err
			}
			return tx.QueryRow(ctx,
				`SELECT id, created_at
				   FROM outbox
				  WHERE tenant_id = $1 AND idempotency_key = $2
				  ORDER BY id
				  LIMIT 1`,
				tenantID, idempotencyKey).Scan(&outboxID, &queuedAt)
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, notificationChannelTestResponse{
			ChannelID:      channel.ID,
			Destination:    notify.DestinationTest,
			OutboxID:       outboxID,
			Status:         "queued",
			CredentialRef:  redactCredentialRef(req.CredentialRef),
			SecretHandling: "credential reference redacted; configured channel credentials are read only by the delivery worker",
			IdempotencyKey: idempotencyKey,
			QueuedAt:       queuedAt.UTC(),
		}, nil
	})
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

func (a *API) decodeNotificationRoutingPolicyRequest(r *http.Request, tenantID, pathID string) (store.NotificationRoutingPolicy, error) {
	if a.store == nil || a.log == nil {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured")
	}
	var req notificationRoutingPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		return store.NotificationRoutingPolicy{}, errWithStatus(http.StatusBadRequest, err)
	}
	id := strings.TrimSpace(pathID)
	if id == "" {
		id = strings.TrimSpace(req.ID)
	}
	if id == "" {
		id = guuid.NewString()
	}
	if _, err := guuid.Parse(id); err != nil {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy id must be a UUID")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy name is required")
	}
	if len(name) > 120 {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy name must be 120 characters or fewer")
	}
	supported := a.supportedNotificationChannels()
	matrix := make(map[string][]string, len(req.ChannelsBySeverity))
	for severity, channels := range req.ChannelsBySeverity {
		canonical, err := normalizeNotificationSeverity(severity)
		if err != nil {
			return store.NotificationRoutingPolicy{}, err
		}
		normalized, err := normalizeRoutingChannels(channels, supported)
		if err != nil {
			return store.NotificationRoutingPolicy{}, err
		}
		if len(normalized) > 0 {
			matrix[canonical] = normalized
		}
	}
	defaults, err := normalizeRoutingChannels(req.DefaultChannels, supported)
	if err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	if len(matrix) == 0 && len(defaults) == 0 {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy requires at least one channel")
	}
	ownerEmail := strings.TrimSpace(req.OwnerEmail)
	if ownerEmail != "" && strings.ContainsAny(ownerEmail, " \t\r\n") {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "owner_email must be one email-like token")
	}
	interval := req.DigestInterval
	if interval == 0 {
		interval = 86400
	}
	if interval < 3600 || interval > 604800 {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "digest_interval_seconds must be between 3600 and 604800")
	}
	timezone := strings.TrimSpace(req.DigestTimezone)
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "digest_timezone must be a valid time zone")
	}
	return store.NotificationRoutingPolicy{
		ID:                 id,
		TenantID:           tenantID,
		Name:               name,
		ChannelsBySeverity: matrix,
		DefaultChannels:    defaults,
		OwnerRef:           strings.TrimSpace(req.OwnerRef),
		OwnerEmail:         ownerEmail,
		DigestInterval:     interval,
		DigestTimezone:     timezone,
	}, nil
}

func (a *API) appendNotificationRoutingPolicyUpsert(ctx context.Context, tenantID string, policy store.NotificationRoutingPolicy) (store.NotificationRoutingPolicy, error) {
	payload, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID:                 policy.ID,
		Name:               policy.Name,
		ChannelsBySeverity: policy.ChannelsBySeverity,
		DefaultChannels:    policy.DefaultChannels,
		OwnerRef:           policy.OwnerRef,
		OwnerEmail:         policy.OwnerEmail,
		DigestInterval:     policy.DigestInterval,
		DigestTimezone:     policy.DigestTimezone,
	})
	if err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	ev, err := a.log.Append(ctx, events.Event{
		Type:     projections.EventNotificationRoutingPolicyUpserted,
		TenantID: tenantID,
		Data:     payload,
	})
	if err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	if err := projections.New(a.store).Apply(ctx, ev); err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	return a.store.GetNotificationRoutingPolicy(ctx, tenantID, policy.ID)
}

func (a *API) supportedNotificationChannels() map[string]bool {
	out := map[string]bool{}
	for _, channel := range notificationChannelCatalog(a.notificationChannels) {
		out[channel.ID] = true
	}
	return out
}

func (a *API) notificationChannelForTest(raw string) (notificationChannelResponse, error) {
	id := canonicalNotificationChannelID(raw)
	if id == "" {
		return notificationChannelResponse{}, errStatus(http.StatusBadRequest, "notification channel id is required")
	}
	for _, channel := range notificationChannelCatalog(a.notificationChannels) {
		if channel.ID != id {
			continue
		}
		if !channel.Configured {
			return notificationChannelResponse{}, errStatus(http.StatusConflict, "notification channel is supported but not configured")
		}
		return channel, nil
	}
	return notificationChannelResponse{}, errStatus(http.StatusBadRequest, "unsupported notification channel")
}

func normalizeNotificationSeverity(raw string) (string, error) {
	severity := strings.ToLower(strings.TrimSpace(raw))
	switch severity {
	case "":
		return notify.AlertSeverityInformational, nil
	case "info":
		return notify.AlertSeverityInformational, nil
	case notify.AlertSeverityLow, notify.AlertSeverityInformational, notify.AlertSeverityWarning, notify.AlertSeverityCritical:
		return severity, nil
	default:
		return "", errStatus(http.StatusBadRequest, "severity must be low, informational, warning, or critical")
	}
}

func normalizeRoutingChannels(channels []string, supported map[string]bool) ([]string, error) {
	seen := make(map[string]bool, len(channels))
	out := make([]string, 0, len(channels))
	for _, raw := range channels {
		id := canonicalNotificationChannelID(raw)
		if id == "" {
			continue
		}
		if !supported[id] {
			return nil, errStatus(http.StatusBadRequest, "unsupported notification channel "+id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

func notificationRoutingPolicyPathID(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.PathValue("id"))
	if _, err := guuid.Parse(id); err != nil {
		return "", errStatus(http.StatusBadRequest, "notification routing policy id must be a UUID")
	}
	return id, nil
}

func toNotificationRoutingPolicyResponse(p store.NotificationRoutingPolicy) notificationRoutingPolicyResponse {
	interval := p.DigestInterval
	if interval <= 0 {
		interval = 86400
	}
	timezone := p.DigestTimezone
	if timezone == "" {
		timezone = "UTC"
	}
	return notificationRoutingPolicyResponse{
		ID:                 p.ID,
		TenantID:           p.TenantID,
		Name:               p.Name,
		ChannelsBySeverity: copyChannelMatrix(p.ChannelsBySeverity),
		DefaultChannels:    append([]string(nil), p.DefaultChannels...),
		OwnerRef:           p.OwnerRef,
		OwnerEmail:         p.OwnerEmail,
		DigestInterval:     interval,
		DigestTimezone:     timezone,
		DigestPreview: notificationDigestPreviewResponse{
			IntervalSeconds: interval,
			Timezone:        timezone,
			NextRunAt:       nextDigestPreview(p.UpdatedAt, interval),
		},
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

func copyChannelMatrix(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func nextDigestPreview(anchor time.Time, intervalSeconds int) time.Time {
	if intervalSeconds <= 0 {
		intervalSeconds = 86400
	}
	interval := time.Duration(intervalSeconds) * time.Second
	if anchor.IsZero() {
		return time.Now().UTC().Add(interval)
	}
	next := anchor.UTC().Add(interval)
	now := time.Now().UTC()
	if next.After(now) {
		return next
	}
	behind := now.Sub(next)
	steps := int64(behind/interval) + 1
	return next.Add(time.Duration(steps) * interval)
}

func redactCredentialRef(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	return "redacted"
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
