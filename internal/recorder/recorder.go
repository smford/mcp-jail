package recorder

import (
	"database/sql"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Recorder asynchronously writes flight recorder events into SQLite.
type Recorder struct {
	db        *sql.DB
	eventChan chan *Event
	sessChan  chan *sessionUpdate
	done      chan struct{}
	wg        sync.WaitGroup
	dbPath    string
}

type sessionUpdate struct {
	ID              string
	Ended           bool
	EndedAt         time.Time
	TotalCalls      int
	BlockedCalls    int
	RedactedSecrets int
	EstTokens       int64
}

// ExpandPath expands ~ to the user's home directory.
func ExpandPath(p string) string {
	if p == "~" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
		return os.Getenv("HOME")
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home := ""
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			home = u.HomeDir
		} else {
			home = os.Getenv("HOME")
		}
		if home != "" {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// NewRecorder opens or creates the SQLite flight recorder database.
func NewRecorder(dbPath string) (*Recorder, error) {
	if dbPath == "" {
		dbPath = "~/.mcp-jail/flight-recorder.db"
	}
	dbPath = ExpandPath(dbPath)

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory %s: %w", dir, err)
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database at %s: %w", dbPath, err)
	}

	// Single writer connection pool works best with SQLite WAL
	db.SetMaxOpenConns(1)

	r := &Recorder{
		db:        db,
		eventChan: make(chan *Event, 10000),
		sessChan:  make(chan *sessionUpdate, 1000),
		done:      make(chan struct{}),
		dbPath:    dbPath,
	}

	if err := r.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize db schema: %w", err)
	}

	r.wg.Add(1)
	go r.worker()

	return r, nil
}

func (r *Recorder) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		started_at TIMESTAMP NOT NULL,
		ended_at TIMESTAMP,
		command TEXT NOT NULL,
		cwd TEXT NOT NULL,
		total_calls INTEGER DEFAULT 0,
		blocked_calls INTEGER DEFAULT 0,
		redacted_secrets INTEGER DEFAULT 0,
		est_tokens INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		timestamp TIMESTAMP NOT NULL,
		direction TEXT NOT NULL,
		rpc_id TEXT,
		method TEXT,
		tool_name TEXT,
		action TEXT NOT NULL,
		rule_triggered TEXT,
		latency_ms INTEGER DEFAULT 0,
		payload_json TEXT,
		FOREIGN KEY(session_id) REFERENCES sessions(id)
	);

	CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);

	CREATE TABLE IF NOT EXISTS file_snapshots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		file_path TEXT NOT NULL,
		snapshot_content BLOB NOT NULL,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY(session_id) REFERENCES sessions(id)
	);

	CREATE INDEX IF NOT EXISTS idx_file_snapshots_session ON file_snapshots(session_id);
	`
	_, err := r.db.Exec(schema)
	return err
}

func (r *Recorder) worker() {
	defer r.wg.Done()

	for {
		select {
		case ev, ok := <-r.eventChan:
			if !ok {
				// Drain session channel as well
				for su := range r.sessChan {
					r.persistSessionUpdate(su)
				}
				return
			}
			r.persistEvent(ev)

		case su, ok := <-r.sessChan:
			if !ok {
				// Drain event channel as well
				for ev := range r.eventChan {
					r.persistEvent(ev)
				}
				return
			}
			r.persistSessionUpdate(su)

		case <-r.done:
			// Flush remaining
			for {
				select {
				case ev := <-r.eventChan:
					r.persistEvent(ev)
				case su := <-r.sessChan:
					r.persistSessionUpdate(su)
				default:
					return
				}
			}
		}
	}
}

func (r *Recorder) persistEvent(ev *Event) {
	query := `INSERT INTO events (
		session_id, timestamp, direction, rpc_id, method, tool_name, action, rule_triggered, latency_ms, payload_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, _ = r.db.Exec(query,
		ev.SessionID,
		ev.Timestamp.Format(time.RFC3339Nano),
		string(ev.Direction),
		ev.RPCID,
		ev.Method,
		ev.ToolName,
		string(ev.Action),
		ev.RuleTriggered,
		ev.LatencyMs,
		ev.PayloadJSON,
	)
}

func (r *Recorder) persistSessionUpdate(su *sessionUpdate) {
	if su.Ended {
		query := `UPDATE sessions SET
			ended_at = ?,
			total_calls = ?,
			blocked_calls = ?,
			redacted_secrets = ?,
			est_tokens = ?
			WHERE id = ?`
		_, _ = r.db.Exec(query,
			su.EndedAt.Format(time.RFC3339Nano),
			su.TotalCalls,
			su.BlockedCalls,
			su.RedactedSecrets,
			su.EstTokens,
			su.ID,
		)
	} else {
		query := `UPDATE sessions SET
			total_calls = ?,
			blocked_calls = ?,
			redacted_secrets = ?,
			est_tokens = ?
			WHERE id = ?`
		_, _ = r.db.Exec(query,
			su.TotalCalls,
			su.BlockedCalls,
			su.RedactedSecrets,
			su.EstTokens,
			su.ID,
		)
	}
}

// StartSession creates a new session synchronously so subsequent events can reference it.
func (r *Recorder) StartSession(sess *Session) error {
	query := `INSERT INTO sessions (
		id, started_at, command, cwd, total_calls, blocked_calls, redacted_secrets, est_tokens
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		sess.ID,
		sess.StartedAt.Format(time.RFC3339Nano),
		sess.Command,
		sess.Cwd,
		sess.TotalCalls,
		sess.BlockedCalls,
		sess.RedactedSecrets,
		sess.EstTokens,
	)
	return err
}

// RecordEvent queues an event for asynchronous insertion.
func (r *Recorder) RecordEvent(ev *Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	select {
	case r.eventChan <- ev:
	default:
		// Fallback synchronously if channel full
		r.persistEvent(ev)
	}
}

// UpdateSessionCounters queues an update to session counters.
func (r *Recorder) UpdateSessionCounters(sessionID string, totalCalls, blockedCalls, redactedSecrets int, estTokens int64) {
	su := &sessionUpdate{
		ID:              sessionID,
		Ended:           false,
		TotalCalls:      totalCalls,
		BlockedCalls:    blockedCalls,
		RedactedSecrets: redactedSecrets,
		EstTokens:       estTokens,
	}
	select {
	case r.sessChan <- su:
	default:
		r.persistSessionUpdate(su)
	}
}

// EndSession queues the session end timestamp and final counters.
func (r *Recorder) EndSession(sessionID string, totalCalls, blockedCalls, redactedSecrets int, estTokens int64) {
	su := &sessionUpdate{
		ID:              sessionID,
		Ended:           true,
		EndedAt:         time.Now(),
		TotalCalls:      totalCalls,
		BlockedCalls:    blockedCalls,
		RedactedSecrets: redactedSecrets,
		EstTokens:       estTokens,
	}
	select {
	case r.sessChan <- su:
	default:
		r.persistSessionUpdate(su)
	}
}

// Close flushes all queued writes and closes the database.
func (r *Recorder) Close() error {
	close(r.eventChan)
	close(r.sessChan)
	r.wg.Wait()
	return r.db.Close()
}

// Query methods

// GetEvents queries logged events matching the filter.
func (r *Recorder) GetEvents(filter EventFilter) ([]*Event, error) {
	query := `SELECT id, session_id, timestamp, direction, rpc_id, method, tool_name, action, rule_triggered, latency_ms, payload_json
		FROM events WHERE 1=1`
	var args []interface{}

	if filter.SessionID != "" {
		query += " AND session_id = ?"
		args = append(args, filter.SessionID)
	}
	if filter.BlockedOnly {
		query += " AND action = ?"
		args = append(args, string(ActionBlocked))
	}
	query += " ORDER BY id ASC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		ev := &Event{}
		var tsStr, dirStr, actStr string
		var rpcID, method, toolName, ruleTriggered, payload sql.NullString

		if err := rows.Scan(
			&ev.ID,
			&ev.SessionID,
			&tsStr,
			&dirStr,
			&rpcID,
			&method,
			&toolName,
			&actStr,
			&ruleTriggered,
			&ev.LatencyMs,
			&payload,
		); err != nil {
			return nil, err
		}

		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
		ev.Direction = Direction(dirStr)
		ev.Action = Action(actStr)
		if rpcID.Valid {
			ev.RPCID = rpcID.String
		}
		if method.Valid {
			ev.Method = method.String
		}
		if toolName.Valid {
			ev.ToolName = toolName.String
		}
		if ruleTriggered.Valid {
			ev.RuleTriggered = ruleTriggered.String
		}
		if payload.Valid {
			ev.PayloadJSON = payload.String
		}

		events = append(events, ev)
	}

	return events, rows.Err()
}

// GetSession retrieves a single session by ID.
func (r *Recorder) GetSession(id string) (*Session, error) {
	query := `SELECT id, started_at, ended_at, command, cwd, total_calls, blocked_calls, redacted_secrets, est_tokens
		FROM sessions WHERE id = ?`

	row := r.db.QueryRow(query, id)
	sess := &Session{}
	var startStr string
	var endStr sql.NullString

	if err := row.Scan(
		&sess.ID,
		&startStr,
		&endStr,
		&sess.Command,
		&sess.Cwd,
		&sess.TotalCalls,
		&sess.BlockedCalls,
		&sess.RedactedSecrets,
		&sess.EstTokens,
	); err != nil {
		return nil, err
	}

	sess.StartedAt, _ = time.Parse(time.RFC3339Nano, startStr)
	if endStr.Valid && endStr.String != "" {
		t, _ := time.Parse(time.RFC3339Nano, endStr.String)
		sess.EndedAt = &t
	}

	return sess, nil
}

// ListSessions lists recent sessions.
func (r *Recorder) ListSessions(limit int) ([]*Session, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `SELECT id, started_at, ended_at, command, cwd, total_calls, blocked_calls, redacted_secrets, est_tokens
		FROM sessions ORDER BY started_at DESC LIMIT ?`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		sess := &Session{}
		var startStr string
		var endStr sql.NullString

		if err := rows.Scan(
			&sess.ID,
			&startStr,
			&endStr,
			&sess.Command,
			&sess.Cwd,
			&sess.TotalCalls,
			&sess.BlockedCalls,
			&sess.RedactedSecrets,
			&sess.EstTokens,
		); err != nil {
			return nil, err
		}

		sess.StartedAt, _ = time.Parse(time.RFC3339Nano, startStr)
		if endStr.Valid && endStr.String != "" {
			t, _ := time.Parse(time.RFC3339Nano, endStr.String)
			sess.EndedAt = &t
		}

		sessions = append(sessions, sess)
	}

	return sessions, rows.Err()
}

// GetStats returns aggregated metrics.
func (r *Recorder) GetStats(sessionID string) (*StatsSummary, error) {
	summary := &StatsSummary{
		SessionID: sessionID,
	}

	var sessQuery string
	var args []interface{}
	if sessionID != "" {
		sessQuery = `SELECT COUNT(1), COALESCE(SUM(total_calls), 0), COALESCE(SUM(blocked_calls), 0),
			COALESCE(SUM(redacted_secrets), 0), COALESCE(SUM(est_tokens), 0)
			FROM sessions WHERE id = ?`
		args = append(args, sessionID)
	} else {
		sessQuery = `SELECT COUNT(1), COALESCE(SUM(total_calls), 0), COALESCE(SUM(blocked_calls), 0),
			COALESCE(SUM(redacted_secrets), 0), COALESCE(SUM(est_tokens), 0)
			FROM sessions`
	}

	row := r.db.QueryRow(sessQuery, args...)
	if err := row.Scan(
		&summary.TotalSessions,
		&summary.TotalCalls,
		&summary.BlockedCalls,
		&summary.RedactedSecrets,
		&summary.EstTokens,
	); err != nil {
		return nil, err
	}

	// Query top tools
	var toolsQuery string
	var toolArgs []interface{}
	if sessionID != "" {
		toolsQuery = `SELECT tool_name, COUNT(1) as cnt
			FROM events
			WHERE session_id = ? AND tool_name IS NOT NULL AND tool_name != ''
			GROUP BY tool_name
			ORDER BY cnt DESC
			LIMIT 10`
		toolArgs = append(toolArgs, sessionID)
	} else {
		toolsQuery = `SELECT tool_name, COUNT(1) as cnt
			FROM events
			WHERE tool_name IS NOT NULL AND tool_name != ''
			GROUP BY tool_name
			ORDER BY cnt DESC
			LIMIT 10`
	}

	tRows, err := r.db.Query(toolsQuery, toolArgs...)
	if err == nil {
		defer tRows.Close()
		for tRows.Next() {
			var tc ToolCount
			if err := tRows.Scan(&tc.ToolName, &tc.Count); err == nil {
				summary.TopTools = append(summary.TopTools, tc)
			}
		}
	}

	return summary, nil
}
