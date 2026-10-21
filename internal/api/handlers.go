package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"crypto/rand"

	"iptables-web/internal/change"
	"iptables-web/internal/iptables"
	appLog "iptables-web/internal/logging"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

type Handler struct {
	store      store.Store
	executor   *iptables.Executor
	mutationMu sync.Mutex
	changeMu   sync.Mutex
	healthMu   sync.Mutex
	healthAt   time.Time
	healthErr  error
	changes    *change.Manager
}

func (h *Handler) SetChangeManager(manager *change.Manager) {
	h.changes = manager
}

func NewHandler(s store.Store, e *iptables.Executor) *Handler {
	return &Handler{
		store:    s,
		executor: e,
	}
}

// ==================== Rules CRUD ====================

func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	chain := r.URL.Query().Get("chain")
	requested := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("backend")))
	var rules []*model.Rule
	var err error
	if requested == "all" {
		rules, err = h.store.List(chain)
	} else {
		backend := model.NormalizeBackend(requested)
		if backend != model.BackendPacket {
			respondError(w, http.StatusBadRequest, "unsupported_backend", "only packet (iptables/iptables-nft) is supported")
			return
		}
		rules, err = h.store.ListByBackend(backend, chain)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if rules == nil {
		rules = []*model.Rule{}
	}
	respondOK(w, rules)
}

func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	id := extractRuleID(r.URL.Path)
	rule, err := h.store.Get(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	respondOK(w, rule)
}

func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()

	var rule model.Rule
	if err := decodeJSONBody(w, r, &rule, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	ruleID, err := newID()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "random_source_failed", "unable to generate a secure rule ID")
		return
	}
	rule.ID = ruleID
	rule.Backend = model.NormalizeBackend(rule.Backend)
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	rule.Position = h.clampRulePosition(rule.Backend, rule.Chain, "", rule.Position)

	if err := rule.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := h.store.Create(&rule); err != nil {
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if err := h.validateStoredTargetOrder(rule.Backend, rule.Chain); err != nil {
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusBadRequest, "unsafe_order", err.Error())
		return
	}
	if err := h.store.Save(); err != nil {
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusInternalServerError, "store_error", fmt.Sprintf("failed to persist rule: %v", err))
		return
	}
	if err := h.syncRuleTarget(rule.Backend, rule.Chain); err != nil {
		_ = h.executor.DeleteRule(&rule)
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(rule.Backend, rule.Chain)
		respondError(w, http.StatusInternalServerError, "iptables_error", fmt.Sprintf("failed to sync rule chain: %v", err))
		return
	}

	respondCreated(w, &rule)
}

func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()
	id := extractRuleID(r.URL.Path)

	existing, err := h.store.Get(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	var updated model.Rule
	if err := decodeJSONBody(w, r, &updated, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	updated.ID = id
	if strings.TrimSpace(updated.Backend) == "" {
		updated.Backend = existing.Backend
	}
	updated.Backend = model.NormalizeBackend(updated.Backend)
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()

	// Preserve existing position if not provided
	if updated.Position == 0 {
		updated.Position = existing.Position
	}
	updated.Position = h.clampRulePosition(updated.Backend, updated.Chain, id, updated.Position)

	if err := updated.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := h.store.Update(&updated); err != nil {
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if err := h.validateStoredTargetOrder(updated.Backend, updated.Chain); err != nil {
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusBadRequest, "unsafe_order", err.Error())
		return
	}
	if existing.Backend != updated.Backend || existing.Chain != updated.Chain {
		if err := h.validateStoredTargetOrder(existing.Backend, existing.Chain); err != nil {
			h.restoreRulesSnapshot(snapshot)
			respondError(w, http.StatusBadRequest, "unsafe_order", err.Error())
			return
		}
	}
	if err := h.executor.DeleteRule(existing); err != nil {
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusInternalServerError, "firewall_error", fmt.Sprintf("failed to remove existing rule: %v", err))
		return
	}
	if err := h.store.Save(); err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTargets(existing, &updated)
		respondError(w, http.StatusInternalServerError, "store_error", fmt.Sprintf("failed to persist updated rule: %v", err))
		return
	}
	if err := h.syncRuleTargets(existing, &updated); err != nil {
		_ = h.executor.DeleteRule(&updated)
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTargets(existing, &updated)
		respondError(w, http.StatusInternalServerError, "iptables_error", fmt.Sprintf("failed to sync updated rule: %v", err))
		return
	}

	respondOK(w, &updated)
}

func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()
	id := extractRuleID(r.URL.Path)

	existing, err := h.store.Get(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	if err := h.executor.DeleteRule(existing); err != nil {
		respondError(w, http.StatusInternalServerError, "firewall_error", fmt.Sprintf("failed to remove rule: %v", err))
		return
	}

	if _, err := h.store.Delete(id); err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(existing.Backend, existing.Chain)
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if err := h.store.Save(); err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(existing.Backend, existing.Chain)
		respondError(w, http.StatusInternalServerError, "store_error", fmt.Sprintf("failed to persist deletion: %v", err))
		return
	}
	if err := h.syncRuleTarget(existing.Backend, existing.Chain); err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(existing.Backend, existing.Chain)
		respondError(w, http.StatusInternalServerError, "iptables_error", fmt.Sprintf("failed to sync deleted rule: %v", err))
		return
	}

	respondNoContent(w)
}

func (h *Handler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()
	id := extractRuleID(r.URL.Path)

	existing, err := h.store.Get(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	if err := h.executor.DeleteRule(existing); err != nil {
		respondError(w, http.StatusInternalServerError, "firewall_error", fmt.Sprintf("failed to remove rule before toggle: %v", err))
		return
	}

	toggled, err := h.store.Toggle(id)
	if err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(existing.Backend, existing.Chain)
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if err := h.validateStoredTargetOrder(existing.Backend, existing.Chain); err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(existing.Backend, existing.Chain)
		respondError(w, http.StatusBadRequest, "unsafe_order", err.Error())
		return
	}
	if err := h.store.Save(); err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(existing.Backend, existing.Chain)
		respondError(w, http.StatusInternalServerError, "store_error", fmt.Sprintf("failed to persist toggle: %v", err))
		return
	}
	if err := h.syncRuleTarget(existing.Backend, existing.Chain); err != nil {
		_ = h.executor.DeleteRule(toggled)
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(existing.Backend, existing.Chain)
		respondError(w, http.StatusInternalServerError, "iptables_error", fmt.Sprintf("failed to sync toggled rule: %v", err))
		return
	}

	respondOK(w, toggled)
}

// ==================== Reorder ====================

func (h *Handler) ReorderRules(w http.ResponseWriter, r *http.Request) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()

	var req model.ReorderRequest
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if !isValidChain(req.Chain) {
		respondError(w, http.StatusBadRequest, "invalid_chain", "invalid chain name")
		return
	}
	req.Backend = model.NormalizeBackend(req.Backend)
	if req.Backend != model.BackendPacket {
		respondError(w, http.StatusBadRequest, "unsupported_backend", "only packet (iptables/iptables-nft) is supported")
		return
	}

	if err := h.validateRuleOrder(req.Backend, req.Chain, req.RuleIDs); err != nil {
		respondError(w, http.StatusBadRequest, "unsafe_order", err.Error())
		return
	}

	if err := h.store.ReorderByTarget(req.Backend, req.Chain, req.RuleIDs); err != nil {
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if err := h.store.Save(); err != nil {
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusInternalServerError, "store_error", fmt.Sprintf("failed to persist reordered rules: %v", err))
		return
	}

	// Re-sync the chain in kernel
	if err := h.syncRuleTarget(req.Backend, req.Chain); err != nil {
		h.restoreRulesSnapshot(snapshot)
		_ = h.syncRuleTarget(req.Backend, req.Chain)
		respondError(w, http.StatusInternalServerError, "iptables_error", fmt.Sprintf("re-sync failed: %v", err))
		return
	}

	chainRules, _ := h.store.ListByTarget(req.Backend, req.Chain)
	respondOK(w, chainRules)
}

// ==================== System ====================

func (h *Handler) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	allRules, _ := h.store.All()
	enabled := 0
	chains := make(map[string]bool)
	for _, rule := range allRules {
		chains[model.NormalizeBackend(rule.Backend)+"/"+rule.Chain] = true
		if rule.Enabled {
			enabled++
		}
	}

	hostname, _ := os.Hostname()
	kernelVer := "unknown"
	if out, err := apiCommandOutput("uname", "-r"); err == nil {
		kernelVer = strings.TrimSpace(string(out))
	}

	backendNames := h.executor.BackendNames()
	backendInfos := make([]model.FirewallBackendInfo, 0, len(backendNames))
	versions := make([]string, 0, len(backendNames))
	for _, id := range []string{model.BackendPacket} {
		name, ok := backendNames[id]
		if !ok {
			continue
		}
		version := firewallVersion(name)
		info := model.FirewallBackendInfo{ID: id, Name: name, Version: version}
		backendInfos = append(backendInfos, info)
		if version != "" {
			versions = append(versions, version)
		} else {
			versions = append(versions, name)
		}
	}

	info := model.SystemInfo{
		FirewallBackend:  h.executor.BackendName(),
		FirewallVersion:  strings.Join(versions, " / "),
		FirewallBackends: backendInfos,
		KernelVersion:    kernelVer,
		Hostname:         hostname,
		ManagedChains:    len(chains),
		TotalRules:       len(allRules),
		EnabledRules:     enabled,
	}
	respondOK(w, info)
}

// userChains lists chains relevant to users (excludes Docker internal chains).
var userChains = map[string]bool{
	"INPUT": true, "FORWARD": true, "OUTPUT": true,
	"DOCKER": true, "DOCKER_USER": true, "DOCKER-USER": true,
}

func (h *Handler) GetChains(w http.ResponseWriter, r *http.Request) {
	backend := requestBackend(r)
	chains, err := h.executor.ListChainsFor(backend)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "iptables_error", err.Error())
		return
	}

	var result []model.ChainInfo
	for _, name := range chains {
		if !userChains[name] {
			continue // skip Docker internal chains
		}
		output, err := h.executor.ListRulesFor(backend, name)
		if err != nil {
			result = append(result, model.ChainInfo{Backend: backend, Name: name, Policy: "?"})
			continue
		}
		parsed, err := iptables.ParseChainOutput(output)
		if err != nil || len(parsed) == 0 {
			result = append(result, model.ChainInfo{Backend: backend, Name: name, Policy: "?"})
			continue
		}
		parsed[0].Backend = backend
		result = append(result, parsed[0])
	}
	respondOK(w, result)
}

func (h *Handler) GetChainRules(w http.ResponseWriter, r *http.Request) {
	backend := requestBackend(r)
	// Extract chain from URL path: /api/v1/system/chains/{chain}/rules
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/system/chains/")
	rest = strings.TrimSuffix(rest, "/rules")
	rest = strings.TrimSuffix(rest, "/")
	chain := rest
	if chain == "" {
		respondError(w, http.StatusBadRequest, "invalid_path", "chain name required")
		return
	}
	output, err := h.executor.ListRulesFor(backend, chain)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "iptables_error", err.Error())
		return
	}
	parsed, err := iptables.ParseChainOutput(output)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "parse_error", err.Error())
		return
	}
	if len(parsed) == 0 {
		respondOK(w, model.ChainInfo{Backend: backend, Name: chain, Policy: "?"})
		return
	}
	parsed[0].Backend = backend
	respondOK(w, parsed[0])
}

func (h *Handler) BackupRules(w http.ResponseWriter, r *http.Request) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	requested := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("backend")))
	if requested == "all" {
		h.backupAllRules(w)
		return
	}
	backend := requestBackend(r)
	data, err := h.executor.BackupFor(backend)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "backup_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-backup.txt", backend))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

type combinedBackupBackend struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	File   string `json:"file,omitempty"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type combinedBackupManifest struct {
	Format           string                  `json:"format"`
	Version          int                     `json:"version"`
	CreatedAt        time.Time               `json:"created_at"`
	ManagedRulesFile string                  `json:"managed_rules_file"`
	Backends         []combinedBackupBackend `json:"backends"`
	Notes            []string                `json:"notes"`
}

type combinedBackupDocument struct {
	Manifest combinedBackupManifest `json:"manifest"`
	Files    map[string]string      `json:"files"`
}

func (h *Handler) backupAllRules(w http.ResponseWriter) {
	files := map[string]string{}
	rules, err := h.store.All()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "backup_error", "read managed rules: "+err.Error())
		return
	}
	managedJSON, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "backup_error", "encode managed rules: "+err.Error())
		return
	}
	files["managed-rules.json"] = string(managedJSON) + "\n"

	manifest := combinedBackupManifest{
		Format:           "iptables-web-combined-backup",
		Version:          1,
		CreatedAt:        time.Now().UTC(),
		ManagedRulesFile: "managed-rules.json",
		Notes: []string{
			"This combined JSON can be submitted directly to the restore endpoint.",
			"Restore only after review and with out-of-band access available.",
		},
	}
	backendNames := h.executor.BackendNames()
	for _, id := range []string{model.BackendPacket} {
		name, ok := backendNames[id]
		if !ok {
			continue
		}
		filename := "packet.rules"
		entry := combinedBackupBackend{ID: id, Name: name, File: filename, Status: "ok"}
		data, backupErr := h.executor.BackupFor(id)
		if backupErr != nil {
			entry.File = ""
			entry.Status = "error"
			entry.Error = backupErr.Error()
		} else {
			files[filename] = data
		}
		manifest.Backends = append(manifest.Backends, entry)
	}
	ipv6Entry := combinedBackupBackend{ID: "packet_ipv6", Name: "ip6tables", File: "packet-ipv6.rules", Status: "ok"}
	if data, backupErr := h.executor.BackupIPv6(); backupErr != nil {
		ipv6Entry.File = ""
		ipv6Entry.Status = "error"
		ipv6Entry.Error = backupErr.Error()
	} else {
		files[ipv6Entry.File] = data
	}
	manifest.Backends = append(manifest.Backends, ipv6Entry)
	document, err := buildCombinedBackup(manifest, files)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "backup_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=iptables-web-complete-%s.json", time.Now().UTC().Format("20060102-150405")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}

func buildCombinedBackup(manifest combinedBackupManifest, files map[string]string) ([]byte, error) {
	document := combinedBackupDocument{Manifest: manifest, Files: files}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode combined backup: %w", err)
	}
	return append(data, '\n'), nil
}

func (h *Handler) RestoreRules(w http.ResponseWriter, r *http.Request) {
	rawBody, err := readRequestBody(w, r, 16*1024*1024)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	restoreData, err := parseRestoreRequestBody(rawBody)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if len(restoreData) > 16*1024*1024 {
		respondError(w, http.StatusBadRequest, "too_large", "restore data exceeds 16MB limit")
		return
	}
	packetData, ipv6Data, managedRules, combined, err := parseRestoreDocument(restoreData)
	if err != nil {
		respondError(w, http.StatusBadRequest, "restore_validation_failed", err.Error())
		return
	}

	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()
	backend := requestBackend(r)
	if err := h.executor.ValidateRestoreFor(backend, packetData); err != nil {
		respondError(w, http.StatusBadRequest, "restore_validation_failed", err.Error())
		return
	}
	if ipv6Data != "" {
		if err := h.executor.ValidateRestoreIPv6(ipv6Data); err != nil {
			respondError(w, http.StatusBadRequest, "restore_validation_failed", err.Error())
			return
		}
	}
	previousPacket, err := h.executor.BackupFor(backend)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "backup_error", "refusing restore without rollback backup: "+err.Error())
		return
	}
	var previousIPv6 string
	if ipv6Data != "" {
		previousIPv6, err = h.executor.BackupIPv6()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "backup_error", "refusing IPv6 restore without rollback backup: "+err.Error())
			return
		}
	}
	if err := h.executor.RestoreFor(backend, packetData); err != nil {
		// A multi-table restore may have committed an earlier table before a
		// later table fails. Do not assume a command error means no changes.
		_ = h.executor.RestoreFor(backend, previousPacket)
		respondError(w, http.StatusInternalServerError, "restore_error", err.Error())
		return
	}
	if ipv6Data != "" {
		if err := h.executor.RestoreIPv6(ipv6Data); err != nil {
			_ = h.executor.RestoreFor(backend, previousPacket)
			_ = h.executor.RestoreIPv6(previousIPv6)
			respondError(w, http.StatusInternalServerError, "restore_error", err.Error())
			return
		}
	}
	if !combined {
		managedRules = make([]*model.Rule, 0, len(snapshot))
		for _, rule := range snapshot {
			if model.NormalizeBackend(rule.Backend) != backend {
				managedRules = append(managedRules, rule)
			}
		}
	} else {
		syncErr := h.executor.SyncRules(managedRules)
		if syncErr == nil {
			syncErr = h.executor.VerifyRules(managedRules)
		}
		if syncErr != nil {
			_ = h.executor.RestoreFor(backend, previousPacket)
			if previousIPv6 != "" {
				_ = h.executor.RestoreIPv6(previousIPv6)
			}
			respondError(w, http.StatusInternalServerError, "restore_error", "restored firewall could not be reconciled with managed metadata: "+syncErr.Error())
			return
		}
	}
	if err := h.store.ReplaceAll(managedRules); err != nil {
		_ = h.executor.RestoreFor(backend, previousPacket)
		if previousIPv6 != "" {
			_ = h.executor.RestoreIPv6(previousIPv6)
		}
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusInternalServerError, "store_error", fmt.Sprintf("restore rolled back after managed-rule update failed: %v", err))
		return
	}
	if err := h.store.Save(); err != nil {
		_ = h.executor.RestoreFor(backend, previousPacket)
		if previousIPv6 != "" {
			_ = h.executor.RestoreIPv6(previousIPv6)
		}
		h.restoreRulesSnapshot(snapshot)
		respondError(w, http.StatusInternalServerError, "store_error", fmt.Sprintf("restore rolled back after managed-rule persistence failed: %v", err))
		return
	}
	respondOK(w, map[string]string{"status": "restored"})
}

func parseRestoreRequestBody(raw []byte) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", fmt.Errorf("恢复请求内容为空")
	}

	// The browser uploads the complete backup JSON directly, avoiding a second
	// JSON-string encoding pass for potentially large rule dumps.
	var document combinedBackupDocument
	if err := json.Unmarshal(raw, &document); err == nil && document.Manifest.Format == "iptables-web-combined-backup" {
		return string(raw), nil
	}

	// Keep compatibility with older clients and raw iptables-save restores.
	var envelope struct {
		Data string `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return "", fmt.Errorf("请选择 iptables-web 下载的完整备份 JSON 文件：%w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", fmt.Errorf("恢复请求只能包含一个 JSON 对象")
	}
	if strings.TrimSpace(envelope.Data) == "" {
		return "", fmt.Errorf("data 字段不能为空")
	}
	return envelope.Data, nil
}

func parseRestoreDocument(data string) (packetData, ipv6Data string, managedRules []*model.Rule, combined bool, err error) {
	packetData = data
	var document combinedBackupDocument
	if json.Unmarshal([]byte(data), &document) != nil || document.Manifest.Format != "iptables-web-combined-backup" {
		return packetData, "", nil, false, nil
	}
	if document.Manifest.Version != 1 {
		return "", "", nil, true, fmt.Errorf("unsupported combined backup version %d", document.Manifest.Version)
	}
	packetData = document.Files["packet.rules"]
	if strings.TrimSpace(packetData) == "" {
		return "", "", nil, true, fmt.Errorf("combined backup is missing packet.rules")
	}
	ipv6Data = document.Files["packet-ipv6.rules"]
	managedName := document.Manifest.ManagedRulesFile
	if managedName == "" {
		managedName = "managed-rules.json"
	}
	managedData, ok := document.Files[managedName]
	if !ok {
		return "", "", nil, true, fmt.Errorf("combined backup is missing %s", managedName)
	}
	if err := json.Unmarshal([]byte(managedData), &managedRules); err != nil {
		return "", "", nil, true, fmt.Errorf("decode managed rules: %w", err)
	}
	seen := make(map[string]bool, len(managedRules))
	for _, rule := range managedRules {
		if rule == nil {
			return "", "", nil, true, fmt.Errorf("managed rules contain a null entry")
		}
		if rule.ID == "" || seen[rule.ID] {
			return "", "", nil, true, fmt.Errorf("managed rules contain an empty or duplicate id %q", rule.ID)
		}
		seen[rule.ID] = true
		if err := rule.Validate(); err != nil {
			return "", "", nil, true, fmt.Errorf("managed rule %s is invalid: %w", rule.ID, err)
		}
	}
	return packetData, ipv6Data, managedRules, true, nil
}

// ClearManagedRules removes only rules represented in rules.json, then clears
// the application store. It never flushes a chain or removes unknown rules.
func (h *Handler) ClearManagedRules(w http.ResponseWriter, r *http.Request) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()

	rules, err := h.store.All()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if len(rules) == 0 {
		respondOK(w, map[string]interface{}{"removed": 0, "status": "empty"})
		return
	}
	if err := h.executor.DeleteRules(rules); err != nil {
		_ = h.executor.SyncRules(rules)
		respondError(w, http.StatusInternalServerError, "firewall_error", "failed to remove all managed rules: "+err.Error())
		return
	}
	if err := h.store.ReplaceAll(nil); err != nil {
		_ = h.executor.SyncRules(rules)
		respondError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if err := h.store.Save(); err != nil {
		_ = h.store.ReplaceAll(rules)
		_ = h.executor.SyncRules(rules)
		respondError(w, http.StatusInternalServerError, "store_error", "clearing the store failed; attempted to restore managed rules: "+err.Error())
		return
	}
	respondOK(w, map[string]interface{}{"removed": len(rules), "status": "cleared"})
}

// ==================== Docker ====================

func (h *Handler) GetDockerMappings(w http.ResponseWriter, r *http.Request) {
	mappings := detectDockerMappings()
	respondOK(w, mappings)
}

func (h *Handler) GetDockerDiagnostics(w http.ResponseWriter, r *http.Request) {
	status := h.executor.DockerPathStatus()
	ip := remoteRequestIP(r.RemoteAddr)
	respondOK(w, map[string]interface{}{
		"client_ip": ip,
		"path":      status,
	})
}

func remoteRequestIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(strings.TrimSpace(remoteAddr), "[]")
}

type dockerWhitelistRequest struct {
	Source        string `json:"source"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
	ContainerName string `json:"container_name"`
	ContainerPort int    `json:"container_port"`
}

func dockerRuleEndpoint(hostIP string, hostPort int, containerName string, containerPort int) string {
	hostIP = strings.Trim(strings.TrimSpace(hostIP), "[]")
	host := fmt.Sprintf("宿主机:%d", hostPort)
	if hostIP != "" && hostIP != "0.0.0.0" && hostIP != "::" {
		host = fmt.Sprintf("%s:%d", hostIP, hostPort)
	}
	name := strings.TrimSpace(containerName)
	if name == "" {
		name = "Docker 容器"
	}
	nameRunes := []rune(name)
	if len(nameRunes) > 80 {
		name = string(nameRunes[:80])
	}
	return fmt.Sprintf("%s → %s:%d", host, name, containerPort)
}

func detectDockerMappings() []model.DockerMapping {
	// 1. Docker socket — most accurate, shows only Docker containers
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		if m, err := detectViaDockerSocket(); err == nil && len(m) > 0 {
			return m
		}
	}

	// 2. Docker CLI — also Docker-specific
	if m, err := detectViaDockerCLI(); err == nil && len(m) > 0 {
		return m
	}

	// Do not guess from /proc. A listening host service is not necessarily a
	// Docker published port and a guessed mapping would create an ineffective
	// DOCKER-USER rule.
	return []model.DockerMapping{}
}

func detectViaDockerSocket() ([]model.DockerMapping, error) {
	// Use HTTP over Unix socket to query Docker API
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", "/var/run/docker.sock")
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	resp, err := client.Get("http://localhost/containers/json?all=false")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Docker API returned %s", resp.Status)
	}

	var containers []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Ports []struct {
			PublicPort  int    `json:"PublicPort"`
			PrivatePort int    `json:"PrivatePort"`
			Type        string `json:"Type"`
			IP          string `json:"IP"`
		} `json:"Ports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, err
	}

	var mappings []model.DockerMapping
	for _, c := range containers {
		name := shortDockerID(c.ID)
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		for _, p := range c.Ports {
			if p.PublicPort > 0 {
				mappings = append(mappings, model.DockerMapping{
					ContainerName: name,
					ContainerID:   shortDockerID(c.ID),
					HostPort:      p.PublicPort,
					ContainerPort: p.PrivatePort,
					Protocol:      p.Type,
					HostIP:        p.IP,
					Family:        dockerAddressFamily(p.IP),
				})
			}
		}
	}
	return mappings, nil
}

func detectViaDockerCLI() ([]model.DockerMapping, error) {
	out, err := apiCommandOutput("docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}")
	if err != nil {
		return nil, err
	}

	var mappings []model.DockerMapping
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		ports := parseDockerPorts(fields[2])
		for _, p := range ports {
			p.ContainerID = shortDockerID(fields[0])
			p.ContainerName = fields[1]
			mappings = append(mappings, p)
		}
	}
	return mappings, nil
}

func shortDockerID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func parseDockerPorts(portsStr string) []model.DockerMapping {
	var result []model.DockerMapping
	parts := strings.Split(portsStr, ", ")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Format: 0.0.0.0:8080->80/tcp or 8080->80/tcp or 8080/tcp
		mapping := model.DockerMapping{}
		arrowIdx := strings.Index(part, "->")
		if arrowIdx >= 0 {
			hostPart := part[:arrowIdx]
			containerPart := part[arrowIdx+2:]

			if idx := strings.LastIndex(hostPart, ":"); idx >= 0 {
				hostPort := hostPart[idx+1:]
				fmt.Sscanf(hostPort, "%d", &mapping.HostPort)
				mapping.HostIP = hostPart[:idx]
			} else {
				fmt.Sscanf(hostPart, "%d", &mapping.HostPort)
			}

			protoIdx := strings.Index(containerPart, "/")
			if protoIdx >= 0 {
				fmt.Sscanf(containerPart[:protoIdx], "%d", &mapping.ContainerPort)
				mapping.Protocol = containerPart[protoIdx+1:]
			} else {
				fmt.Sscanf(containerPart, "%d", &mapping.ContainerPort)
			}
		} else {
			// "80/tcp" is an exposed but unpublished container port. It has no
			// host-side port and must not appear as a manageable mapping.
			continue
		}
		if mapping.HostPort > 0 {
			mapping.Family = dockerAddressFamily(mapping.HostIP)
			result = append(result, mapping)
		}
	}
	return result
}

func dockerAddressFamily(hostIP string) string {
	hostIP = strings.Trim(strings.TrimSpace(hostIP), "[]")
	if strings.Contains(hostIP, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// extractRuleID extracts the rule ID from URL paths like /api/v1/rules/{id} or /api/v1/rules/{id}/toggle
func extractRuleID(path string) string {
	rest := strings.TrimPrefix(path, "/api/v1/rules/")
	rest = strings.TrimSuffix(rest, "/toggle")
	rest = strings.TrimSuffix(rest, "/")
	return rest
}

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	available := h.executor.BackendNames()
	if len(available) == 0 {
		respondError(w, http.StatusServiceUnavailable, "firewall_unavailable", "cannot access firewall backend")
		return
	}
	if err := h.cachedHealthError(); err != nil {
		appLog.Warnf("firewall drift detected by health check: %v", err)
		respondError(w, http.StatusServiceUnavailable, "firewall_drift", "managed firewall rules are not fully applied")
		return
	}
	respondOK(w, map[string]interface{}{"status": "ok", "backends": available})
}

func (h *Handler) cachedHealthError() error {
	h.healthMu.Lock()
	defer h.healthMu.Unlock()
	if time.Since(h.healthAt) < 5*time.Second {
		return h.healthErr
	}
	rules, err := h.store.All()
	if err == nil {
		err = h.executor.VerifyRules(rules)
	}
	h.healthAt = time.Now()
	h.healthErr = err
	return err
}

func (h *Handler) clampRulePosition(backend, chain, excludeID string, position int) int {
	chain = strings.ToUpper(strings.TrimSpace(chain))
	rules, err := h.store.ListByTarget(backend, chain)
	if err != nil {
		return 1
	}
	max := 1
	for _, rule := range rules {
		if rule.ID == excludeID {
			continue
		}
		max++
	}
	if position < 1 || position > max {
		return max
	}
	return position
}

func (h *Handler) validateRuleOrder(backend, chain string, ids []string) error {
	currentRules, err := h.store.ListByTarget(backend, chain)
	if err != nil {
		return err
	}
	byID := make(map[string]*model.Rule, len(currentRules))
	for _, rule := range currentRules {
		byID[rule.ID] = rule
	}
	if len(ids) != len(byID) {
		return fmt.Errorf("reorder requires all %d rule ids for chain %s", len(byID), chain)
	}

	ordered := make([]*model.Rule, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		rule, ok := byID[id]
		if !ok {
			return fmt.Errorf("rule %s does not belong to chain %s", id, chain)
		}
		if seen[id] {
			return fmt.Errorf("duplicate rule id %s", id)
		}
		seen[id] = true
		ordered = append(ordered, rule)
	}

	return validateOrderedRules(chain, ordered)
}

func (h *Handler) validateStoredTargetOrder(backend, chain string) error {
	rules, err := h.store.ListByTarget(backend, chain)
	if err != nil {
		return err
	}
	return validateOrderedRules(chain, rules)
}

func validateOrderedRules(chain string, ordered []*model.Rule) error {
	for i, blocker := range ordered {
		if !blocker.Enabled {
			continue
		}
		if !isSourcelessDrop(blocker) {
			continue
		}
		for j := i + 1; j < len(ordered); j++ {
			later := ordered[j]
			if !later.Enabled {
				continue
			}
			if strings.ToUpper(later.Action) != "ACCEPT" || later.Source == "" {
				continue
			}
			if dropBlocksAccept(blocker, later) {
				port := blocker.DPort
				if port == "" {
					port = later.DPort
				}
				if port == "" {
					port = "all ports"
				}
				return fmt.Errorf("unsafe order: %s for %s would be before ACCEPT for %s on %s", blocker.Action, port, later.Source, chain)
			}
		}
	}
	return nil
}

func isSourcelessDrop(rule *model.Rule) bool {
	action := strings.ToUpper(rule.Action)
	return (action == "DROP" || action == "REJECT") && rule.Source == "" && rule.Dest == ""
}

func dropBlocksAccept(dropRule, acceptRule *model.Rule) bool {
	dropProto := strings.ToLower(dropRule.Protocol)
	acceptProto := strings.ToLower(acceptRule.Protocol)
	if dropProto != "" && dropProto != "all" && dropProto != acceptProto {
		return false
	}
	if dropRule.DPort != "" && dropRule.DPort != acceptRule.DPort {
		return false
	}
	if dropRule.OriginalDPort != "" && dropRule.OriginalDPort != acceptRule.OriginalDPort {
		return false
	}
	if dropRule.OriginalDest != "" && dropRule.OriginalDest != acceptRule.OriginalDest {
		return false
	}
	if dropRule.SPort != "" && dropRule.SPort != acceptRule.SPort {
		return false
	}
	if dropRule.InIface != "" && dropRule.InIface != acceptRule.InIface {
		return false
	}
	if dropRule.OutIface != "" && dropRule.OutIface != acceptRule.OutIface {
		return false
	}
	return true
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func (h *Handler) snapshotRules() []*model.Rule {
	rules, err := h.store.All()
	if err != nil {
		return nil
	}
	return cloneRules(rules)
}

func (h *Handler) restoreRulesSnapshot(snapshot []*model.Rule) {
	if err := h.store.ReplaceAll(cloneRules(snapshot)); err != nil {
		appLog.Warnf("failed to restore rules snapshot: %v", err)
		return
	}
	if err := h.store.Save(); err != nil {
		appLog.Warnf("failed to persist restored rules snapshot: %v", err)
	}
}

func (h *Handler) syncRuleTarget(backend, chain string) error {
	backend = model.NormalizeBackend(backend)
	rules, err := h.store.ListByTarget(backend, chain)
	if err != nil {
		return err
	}
	if err := h.executor.SyncRules(rules); err != nil {
		return err
	}
	return h.executor.VerifyRules(rules)
}

func (h *Handler) syncRuleTargets(rules ...*model.Rule) error {
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		backend := model.NormalizeBackend(rule.Backend)
		chain := strings.ToUpper(strings.TrimSpace(rule.Chain))
		key := backend + "\x00" + chain
		if chain == "" || seen[key] {
			continue
		}
		seen[key] = true
		if err := h.syncRuleTarget(backend, chain); err != nil {
			return err
		}
	}
	return nil
}

func cloneRules(rules []*model.Rule) []*model.Rule {
	if len(rules) == 0 {
		return nil
	}
	cloned := make([]*model.Rule, len(rules))
	for i, rule := range rules {
		if rule == nil {
			continue
		}
		cp := *rule
		cloned[i] = &cp
	}
	return cloned
}

var allowedChainsSet = map[string]bool{
	"INPUT": true, "FORWARD": true, "OUTPUT": true, "DOCKER": true, "DOCKER_USER": true,
}

func isValidChain(chain string) bool {
	return allowedChainsSet[strings.ToUpper(strings.TrimSpace(chain))]
}

func requestBackend(r *http.Request) string {
	return model.NormalizeBackend(r.URL.Query().Get("backend"))
}

func firewallVersion(name string) string {
	var bin string
	var args []string
	switch name {
	case "iptables", "iptables-nft", "iptables-legacy":
		bin, args = name, []string{"--version"}
	case "nftables":
		bin, args = "nft", []string{"--version"}
	default:
		return name
	}
	out, err := apiCommandOutput(bin, args...)
	if err != nil {
		return name
	}
	version := strings.TrimSpace(string(out))
	return version
}

func apiCommandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}
