package store

import "context"

// Commit bounded batches so normal requests can use the database between them.
// Return the committed count even when a later batch fails or is interrupted.
func (s *Store) PruneAuditBefore(ctx context.Context, cutoff int64) (int64, error) {
	const batchSize = 1000
	var removed int64
	for {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		result, err := s.DB.ExecContext(ctx, `DELETE FROM audit_events WHERE id IN
		 (SELECT id FROM audit_events WHERE created_at<=? ORDER BY created_at,id LIMIT ?)`, cutoff, batchSize)
		if err != nil {
			return removed, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return removed, err
		}
		removed += count
		if count < batchSize {
			return removed, nil
		}
	}
}
