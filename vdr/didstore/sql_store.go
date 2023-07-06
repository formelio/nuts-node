package didstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"sort"
	"time"
)

var _ Store = (*sqlStore)(nil)

type sqlStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) (Store, error) {
	s := &sqlStore{
		db: db,
	}
	err := s.migrate()
	return s, err
}

func (s sqlStore) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS did_documents (
			did VARCHAR(1000) NOT NULL,
			tx_ref VARCHAR(255) NOT NULL PRIMARY KEY,
			clock INTEGER NOT NULL,
			hash VARCHAR(255) NOT NULL UNIQUE,
			deactivated BOOLEAN NOT NULL,
       		timestamp TIMESTAMP NOT NULL,
       		version INTEGER NOT NULL,
       		data JSON NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS did_prevs (
		    did VARCHAR(1000) NOT NULL,
			tx_ref VARCHAR(255) NOT NULL,
			prev_hash VARCHAR(255) NOT NULL
		)`,
		`CREATE OR REPLACE VIEW did_documents_current_versions AS
			SELECT did, tx_ref, data
			FROM did_documents docs
			WHERE NOT EXISTS(
				SELECT 1
				FROM did_prevs
				WHERE did=docs.did AND docs.tx_ref=prev_hash)`,
		`CREATE INDEX IF NOT EXISTS did_documents_id ON did_documents (did)`,
		`CREATE INDEX IF NOT EXISTS did_prevs_tx ON did_prevs (tx_ref)`,
		`ALTER TABLE did_prevs ADD CONSTRAINT fk_did_prev_tx FOREIGN KEY(tx_ref) REFERENCES did_documents(tx_ref)`,
		`ALTER TABLE did_prevs ADD CONSTRAINT uq_did_prevs UNIQUE (tx_ref, prev_hash)`,
	}

	for _, statement := range statements {
		_, err := s.db.Exec(statement)
		// Ignore errors for duplicate constraints
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			switch pqErr.Code.Name() {
			case "duplicate_object":
				fallthrough
			case "duplicate_table":
				// this is OK
				continue
			default:
				// this is not OK
			}
		}
		if err != nil {
			return fmt.Errorf("failed to execute migration statement %s: %w", statement, err)
		}
	}
	return nil
}

func (s sqlStore) Add(didDocument did.Document, tx Transaction) error {
	// Get version of last version, to determine the new version
	var version int

	if len(tx.Previous) > 1 {
		return errors.New("multiple previous transactions not supported yet")
	}

	err := s.db.QueryRow("SELECT last.version "+
		"FROM did_documents doc INNER JOIN ( "+
		" SELECT MAX(version) AS version "+
		" FROM did_documents "+
		" WHERE did=$1 "+
		") AS last ON doc.version = last.version "+
		"WHERE doc.did=$1",
		didDocument.ID.String()).Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get max version of DID document (did=%s): %w", didDocument.ID, err)
	}
	version++

	// Then, insert
	data, _ := didDocument.MarshalJSON()
	_, err = s.db.Exec("INSERT INTO did_documents "+
		"(did, tx_ref, hash, data, deactivated, timestamp, version, clock) "+
		"VALUES "+
		"($1, $2, $3, $4, $5, $6, $7, $8)",
		didDocument.ID.String(), tx.Ref.String(), tx.PayloadHash.String(), data, isDeactivated(didDocument),
		tx.SigningTime, version, tx.Clock)
	// Duplicates should be ignored
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code.Name() == "unique_violation" && pqErr.Constraint == "did_documents_pkey" {
		// Duplicate entry (txRef), ignore
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to insert DID document (did=%s): %w", didDocument.ID, err)
	}

	// Insert previous TXs (but only if the TXs is about the same DID)
	for _, prev := range tx.Previous {
		_, err = s.db.Exec("INSERT INTO did_prevs (did, tx_ref, prev_hash) VALUES ($1, $2, $3)", didDocument.ID.String(), tx.Ref.String(), prev.String())
		if err != nil {
			return fmt.Errorf("failed to insert previous transaction (txRef=%s, prev=%s): %w", tx.Ref, prev, err)
		}
	}

	// Now sort all versions of this DID document
	if err = s.sortVersions(didDocument); err != nil {
		return err
	}

	return nil
}

func (s sqlStore) Conflicted(fn types.DocIterator) error {
	return nil
}

func (s sqlStore) ConflictedCount() (uint, error) {
	var count uint
	err := s.db.QueryRow("SELECT COUNT(counts.num) " +
		"FROM (" +
		"	SELECT COUNT(did) num " +
		"	FROM did_documents_current_versions " +
		"	GROUP BY did " +
		"	HAVING COUNT(did) > 1" +
		") AS counts").Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return count, nil
}

func (s sqlStore) DocumentCount() (uint, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(DISTINCT did) FROM did_documents GROUP BY did").Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return uint(count), nil
}

func (s sqlStore) Iterate(fn types.DocIterator) error {
	rows, err := s.db.Query("SELECT did, data FROM did_documents")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return err
		}
		var document did.Document
		if err := json.Unmarshal(data, &document); err != nil {
			return fmt.Errorf("failed to unmarshal DID document (did=%s): %w", id, err)
		}
		if err := fn(document, types.DocumentMetadata{}); err != nil {
			return err
		}
	}
	return nil
}

func (s sqlStore) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	var query string
	var queryArgs []interface{}
	var queryName string

	if metadata != nil {
		if metadata.Hash != nil {
			queryName = "hash"
			query = "SELECT tx_ref, data FROM did_documents_current_versions WHERE hash=$1"
			queryArgs = []interface{}{metadata.Hash.String()}
		}
	} else {
		queryName = "latest"
		query = "SELECT tx_ref, data FROM did_documents_current_versions WHERE did=$1"
		queryArgs = []interface{}{id.String()}
	}
	document, md, err := s.queryDocument(query, queryArgs...)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve DID version failed (%s, did=%s): %w", id, queryName, err)
	}
	// Was the document found?
	if document == nil {
		return nil, nil, types.ErrNotFound
	}
	// Do we allow deactivated documents?
	if isDeactivated(*document) && (metadata == nil || !metadata.AllowDeactivated) {
		return nil, nil, types.ErrDeactivated
	}
	// Do we need to filter on SourceTransaction?
	if metadata != nil && len(metadata.SourceTransaction) > 0 {
		var matches bool
	outer:
		for _, tx1 := range md.SourceTransactions {
			if tx1.Equals(*metadata.SourceTransaction) {
				matches = true
				break outer
			}
		}
		if !matches {
			return nil, nil, types.ErrNotFound
		}
	}
	return document, md, nil
}

func (s sqlStore) queryDocument(query string, args ...interface{}) (*did.Document, *types.DocumentMetadata, error) {
	rows, err := s.db.Query(query, args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("query failure: %w", err)
	}
	defer rows.Close()

	var txRefString string
	var data []byte
	var versions []Transaction
	for rows.Next() {
		err := rows.Scan(&txRefString, &data)
		if err != nil {
			return nil, nil, fmt.Errorf("scan failure: %w", err)
		}
		var document did.Document
		if err := json.Unmarshal(data, &document); err != nil {
			return nil, nil, fmt.Errorf("unmarshal failure (tx=%s): %w", txRefString, err)
		}
		txRef, err := hash.ParseHex(txRefString)
		if err != nil {
			return nil, nil, err
		}

		// Find prevs
		// TODO: These could be queried at once with either a JOIN or array_agg
		prevs, err := s.findPrevs(txRef)
		if err != nil {
			return nil, nil, err
		}
		versions = append(versions, Transaction{
			Ref:      txRef,
			document: &document,
			Previous: prevs,
		})
	}

	switch len(versions) {
	case 0:
		return nil, nil, nil
	case 1:
		md := types.DocumentMetadata{
			Hash:               hash.SHA256Sum(data), // TODO: should we use the stored hash instead?
			SourceTransactions: []hash.SHA256Hash{versions[0].Ref},
		}
		if len(versions[0].Previous) > 0 {
			// TODO: this should be the hash of the DID document, not of the TX ref
			md.PreviousHash = &versions[0].Previous[0]
		}
		return versions[0].document, &md, nil
	default:
		// conflicted
		var mergedDocument = *versions[0].document
		var sourceTXs []hash.SHA256Hash
		for i, version := range versions {
			sourceTXs = append(sourceTXs, version.Ref)
			if i == 0 {
				continue
			}
			mergedDocument = mergeDocuments(mergedDocument, *version.document)
		}
		mergedDocumentBytes, _ := json.Marshal(mergedDocument)
		md := types.DocumentMetadata{
			// TODO: What about PrevousHash?
			SourceTransactions: sourceTXs,
			Hash:               hash.SHA256Sum(mergedDocumentBytes),
		}
		return &mergedDocument, &md, nil
	}
}

// findPrevs finds all prevs of a DID document transaction
func (s sqlStore) findPrevs(txRef hash.SHA256Hash) ([]hash.SHA256Hash, error) {
	rows, err := s.db.Query("SELECT prev_hash FROM did_prevs WHERE tx_ref=$1", txRef.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query prevs (tx=%s): %w", txRef, err)
	}
	defer rows.Close()
	var prevs []hash.SHA256Hash
	for rows.Next() {
		var str string
		if err := rows.Scan(&str); err != nil {
			return nil, fmt.Errorf("failed to scan prev (tx=%s): %w", txRef, err)
		}
		prev, err := hash.ParseHex(str)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prev (tx=%s): %w", txRef, err)
		}
		prevs = append(prevs, prev)
	}
	return prevs, nil
}

func (s sqlStore) sortVersions(didDocument did.Document) error {
	type record struct {
		txRef     string
		clock     uint32
		timestamp time.Time
		version   int
		hash      sql.NullString
	}

	rows, err := s.db.Query("SELECT tx_ref, clock, timestamp, version, hash FROM did_documents WHERE did = $1 ORDER BY version ASC", didDocument.ID.String())
	if err != nil {
		return fmt.Errorf("failed to query DID document versions (did=%s): %w", didDocument.ID, err)
	}
	defer rows.Close()
	var unsortedRecords []*record
	for rows.Next() {
		var curr record
		if err := rows.Scan(&curr.txRef, &curr.clock, &curr.timestamp, &curr.version, &curr.hash); err != nil {
			return fmt.Errorf("failed to scan DID document versions (did=%s): %w", didDocument.ID, err)
		}
		unsortedRecords = append(unsortedRecords, &curr)
	}
	var sortedRecords = append([]*record{}, unsortedRecords...)
	// TODO: Generated by Copilot, is this right?
	sort.SliceStable(sortedRecords, func(i, j int) bool {
		if sortedRecords[i].clock == sortedRecords[j].clock {
			return sortedRecords[i].timestamp.Before(sortedRecords[j].timestamp)
		}
		return sortedRecords[i].clock < sortedRecords[j].clock
	})

	// Document is conflicted if there's more than one record that is not referred to by another record
	// If that's the case, mark all of these records as conflicted.

	// Check unsorted vs sorted lists, only update changed records
	updateIdx := -1
	for i, unsortedRecord := range unsortedRecords {
		if *unsortedRecord != *sortedRecords[i] {
			// Versions need to be updated starting this record
			updateIdx = i
			break
		}
	}
	if updateIdx == -1 {
		// No changes in order; nothing to do
		return nil
	}

	// Update versions starting at updateIdx
	for i := updateIdx; i < len(sortedRecords); i++ {
		_, err := s.db.Exec("UPDATE did_documents SET version=$1 WHERE tx_ref=$2",
			i+1, sortedRecords[i].txRef)
		if err != nil {
			return fmt.Errorf("failed to update DID document version (did=%s): %w", didDocument.ID, err)
		}
	}

	return nil
}
