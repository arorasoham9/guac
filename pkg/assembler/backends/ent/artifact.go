// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
)

// Artifact is the model entity for the Artifact schema.
type Artifact struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// Algorithm holds the value of the "algorithm" field.
	Algorithm string `json:"algorithm,omitempty"`
	// Digest holds the value of the "digest" field.
	Digest string `json:"digest,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ArtifactQuery when eager-loading is set.
	Edges        ArtifactEdges `json:"edges"`
	selectValues sql.SelectValues
}

// ArtifactEdges holds the relations/edges for other nodes in the graph.
type ArtifactEdges struct {
	// Occurrences holds the value of the occurrences edge.
	Occurrences []*Occurrence `json:"occurrences,omitempty"`
	// Sbom holds the value of the sbom edge.
	Sbom []*BillOfMaterials `json:"sbom,omitempty"`
	// Attestations holds the value of the attestations edge.
	Attestations []*SLSAAttestation `json:"attestations,omitempty"`
	// AttestationsSubject holds the value of the attestations_subject edge.
	AttestationsSubject []*SLSAAttestation `json:"attestations_subject,omitempty"`
	// HashEqualArtA holds the value of the hash_equal_art_a edge.
	HashEqualArtA []*HashEqual `json:"hash_equal_art_a,omitempty"`
	// HashEqualArtB holds the value of the hash_equal_art_b edge.
	HashEqualArtB []*HashEqual `json:"hash_equal_art_b,omitempty"`
	// Vex holds the value of the vex edge.
	Vex []*CertifyVex `json:"vex,omitempty"`
	// Certification holds the value of the certification edge.
	Certification []*Certification `json:"certification,omitempty"`
	// Metadata holds the value of the metadata edge.
	Metadata []*HasMetadata `json:"metadata,omitempty"`
	// Poc holds the value of the poc edge.
	Poc []*PointOfContact `json:"poc,omitempty"`
	// IncludedInSboms holds the value of the included_in_sboms edge.
	IncludedInSboms []*BillOfMaterials `json:"included_in_sboms,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [11]bool
	// totalCount holds the count of the edges above.
	totalCount [11]map[string]int

	namedOccurrences         map[string][]*Occurrence
	namedSbom                map[string][]*BillOfMaterials
	namedAttestations        map[string][]*SLSAAttestation
	namedAttestationsSubject map[string][]*SLSAAttestation
	namedHashEqualArtA       map[string][]*HashEqual
	namedHashEqualArtB       map[string][]*HashEqual
	namedVex                 map[string][]*CertifyVex
	namedCertification       map[string][]*Certification
	namedMetadata            map[string][]*HasMetadata
	namedPoc                 map[string][]*PointOfContact
	namedIncludedInSboms     map[string][]*BillOfMaterials
}

// OccurrencesOrErr returns the Occurrences value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) OccurrencesOrErr() ([]*Occurrence, error) {
	if e.loadedTypes[0] {
		return e.Occurrences, nil
	}
	return nil, &NotLoadedError{edge: "occurrences"}
}

// SbomOrErr returns the Sbom value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) SbomOrErr() ([]*BillOfMaterials, error) {
	if e.loadedTypes[1] {
		return e.Sbom, nil
	}
	return nil, &NotLoadedError{edge: "sbom"}
}

// AttestationsOrErr returns the Attestations value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) AttestationsOrErr() ([]*SLSAAttestation, error) {
	if e.loadedTypes[2] {
		return e.Attestations, nil
	}
	return nil, &NotLoadedError{edge: "attestations"}
}

// AttestationsSubjectOrErr returns the AttestationsSubject value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) AttestationsSubjectOrErr() ([]*SLSAAttestation, error) {
	if e.loadedTypes[3] {
		return e.AttestationsSubject, nil
	}
	return nil, &NotLoadedError{edge: "attestations_subject"}
}

// HashEqualArtAOrErr returns the HashEqualArtA value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) HashEqualArtAOrErr() ([]*HashEqual, error) {
	if e.loadedTypes[4] {
		return e.HashEqualArtA, nil
	}
	return nil, &NotLoadedError{edge: "hash_equal_art_a"}
}

// HashEqualArtBOrErr returns the HashEqualArtB value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) HashEqualArtBOrErr() ([]*HashEqual, error) {
	if e.loadedTypes[5] {
		return e.HashEqualArtB, nil
	}
	return nil, &NotLoadedError{edge: "hash_equal_art_b"}
}

// VexOrErr returns the Vex value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) VexOrErr() ([]*CertifyVex, error) {
	if e.loadedTypes[6] {
		return e.Vex, nil
	}
	return nil, &NotLoadedError{edge: "vex"}
}

// CertificationOrErr returns the Certification value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) CertificationOrErr() ([]*Certification, error) {
	if e.loadedTypes[7] {
		return e.Certification, nil
	}
	return nil, &NotLoadedError{edge: "certification"}
}

// MetadataOrErr returns the Metadata value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) MetadataOrErr() ([]*HasMetadata, error) {
	if e.loadedTypes[8] {
		return e.Metadata, nil
	}
	return nil, &NotLoadedError{edge: "metadata"}
}

// PocOrErr returns the Poc value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) PocOrErr() ([]*PointOfContact, error) {
	if e.loadedTypes[9] {
		return e.Poc, nil
	}
	return nil, &NotLoadedError{edge: "poc"}
}

// IncludedInSbomsOrErr returns the IncludedInSboms value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) IncludedInSbomsOrErr() ([]*BillOfMaterials, error) {
	if e.loadedTypes[10] {
		return e.IncludedInSboms, nil
	}
	return nil, &NotLoadedError{edge: "included_in_sboms"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Artifact) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case artifact.FieldAlgorithm, artifact.FieldDigest:
			values[i] = new(sql.NullString)
		case artifact.FieldID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Artifact fields.
func (a *Artifact) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case artifact.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				a.ID = *value
			}
		case artifact.FieldAlgorithm:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field algorithm", values[i])
			} else if value.Valid {
				a.Algorithm = value.String
			}
		case artifact.FieldDigest:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field digest", values[i])
			} else if value.Valid {
				a.Digest = value.String
			}
		default:
			a.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Artifact.
// This includes values selected through modifiers, order, etc.
func (a *Artifact) Value(name string) (ent.Value, error) {
	return a.selectValues.Get(name)
}

// QueryOccurrences queries the "occurrences" edge of the Artifact entity.
func (a *Artifact) QueryOccurrences() *OccurrenceQuery {
	return NewArtifactClient(a.config).QueryOccurrences(a)
}

// QuerySbom queries the "sbom" edge of the Artifact entity.
func (a *Artifact) QuerySbom() *BillOfMaterialsQuery {
	return NewArtifactClient(a.config).QuerySbom(a)
}

// QueryAttestations queries the "attestations" edge of the Artifact entity.
func (a *Artifact) QueryAttestations() *SLSAAttestationQuery {
	return NewArtifactClient(a.config).QueryAttestations(a)
}

// QueryAttestationsSubject queries the "attestations_subject" edge of the Artifact entity.
func (a *Artifact) QueryAttestationsSubject() *SLSAAttestationQuery {
	return NewArtifactClient(a.config).QueryAttestationsSubject(a)
}

// QueryHashEqualArtA queries the "hash_equal_art_a" edge of the Artifact entity.
func (a *Artifact) QueryHashEqualArtA() *HashEqualQuery {
	return NewArtifactClient(a.config).QueryHashEqualArtA(a)
}

// QueryHashEqualArtB queries the "hash_equal_art_b" edge of the Artifact entity.
func (a *Artifact) QueryHashEqualArtB() *HashEqualQuery {
	return NewArtifactClient(a.config).QueryHashEqualArtB(a)
}

// QueryVex queries the "vex" edge of the Artifact entity.
func (a *Artifact) QueryVex() *CertifyVexQuery {
	return NewArtifactClient(a.config).QueryVex(a)
}

// QueryCertification queries the "certification" edge of the Artifact entity.
func (a *Artifact) QueryCertification() *CertificationQuery {
	return NewArtifactClient(a.config).QueryCertification(a)
}

// QueryMetadata queries the "metadata" edge of the Artifact entity.
func (a *Artifact) QueryMetadata() *HasMetadataQuery {
	return NewArtifactClient(a.config).QueryMetadata(a)
}

// QueryPoc queries the "poc" edge of the Artifact entity.
func (a *Artifact) QueryPoc() *PointOfContactQuery {
	return NewArtifactClient(a.config).QueryPoc(a)
}

// QueryIncludedInSboms queries the "included_in_sboms" edge of the Artifact entity.
func (a *Artifact) QueryIncludedInSboms() *BillOfMaterialsQuery {
	return NewArtifactClient(a.config).QueryIncludedInSboms(a)
}

// Update returns a builder for updating this Artifact.
// Note that you need to call Artifact.Unwrap() before calling this method if this Artifact
// was returned from a transaction, and the transaction was committed or rolled back.
func (a *Artifact) Update() *ArtifactUpdateOne {
	return NewArtifactClient(a.config).UpdateOne(a)
}

// Unwrap unwraps the Artifact entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (a *Artifact) Unwrap() *Artifact {
	_tx, ok := a.config.driver.(*txDriver)
	if !ok {
		panic("ent: Artifact is not a transactional entity")
	}
	a.config.driver = _tx.drv
	return a
}

// String implements the fmt.Stringer.
func (a *Artifact) String() string {
	var builder strings.Builder
	builder.WriteString("Artifact(")
	builder.WriteString(fmt.Sprintf("id=%v, ", a.ID))
	builder.WriteString("algorithm=")
	builder.WriteString(a.Algorithm)
	builder.WriteString(", ")
	builder.WriteString("digest=")
	builder.WriteString(a.Digest)
	builder.WriteByte(')')
	return builder.String()
}

// NamedOccurrences returns the Occurrences named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedOccurrences(name string) ([]*Occurrence, error) {
	if a.Edges.namedOccurrences == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedOccurrences[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedOccurrences(name string, edges ...*Occurrence) {
	if a.Edges.namedOccurrences == nil {
		a.Edges.namedOccurrences = make(map[string][]*Occurrence)
	}
	if len(edges) == 0 {
		a.Edges.namedOccurrences[name] = []*Occurrence{}
	} else {
		a.Edges.namedOccurrences[name] = append(a.Edges.namedOccurrences[name], edges...)
	}
}

// NamedSbom returns the Sbom named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedSbom(name string) ([]*BillOfMaterials, error) {
	if a.Edges.namedSbom == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedSbom[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedSbom(name string, edges ...*BillOfMaterials) {
	if a.Edges.namedSbom == nil {
		a.Edges.namedSbom = make(map[string][]*BillOfMaterials)
	}
	if len(edges) == 0 {
		a.Edges.namedSbom[name] = []*BillOfMaterials{}
	} else {
		a.Edges.namedSbom[name] = append(a.Edges.namedSbom[name], edges...)
	}
}

// NamedAttestations returns the Attestations named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedAttestations(name string) ([]*SLSAAttestation, error) {
	if a.Edges.namedAttestations == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedAttestations[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedAttestations(name string, edges ...*SLSAAttestation) {
	if a.Edges.namedAttestations == nil {
		a.Edges.namedAttestations = make(map[string][]*SLSAAttestation)
	}
	if len(edges) == 0 {
		a.Edges.namedAttestations[name] = []*SLSAAttestation{}
	} else {
		a.Edges.namedAttestations[name] = append(a.Edges.namedAttestations[name], edges...)
	}
}

// NamedAttestationsSubject returns the AttestationsSubject named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedAttestationsSubject(name string) ([]*SLSAAttestation, error) {
	if a.Edges.namedAttestationsSubject == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedAttestationsSubject[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedAttestationsSubject(name string, edges ...*SLSAAttestation) {
	if a.Edges.namedAttestationsSubject == nil {
		a.Edges.namedAttestationsSubject = make(map[string][]*SLSAAttestation)
	}
	if len(edges) == 0 {
		a.Edges.namedAttestationsSubject[name] = []*SLSAAttestation{}
	} else {
		a.Edges.namedAttestationsSubject[name] = append(a.Edges.namedAttestationsSubject[name], edges...)
	}
}

// NamedHashEqualArtA returns the HashEqualArtA named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedHashEqualArtA(name string) ([]*HashEqual, error) {
	if a.Edges.namedHashEqualArtA == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedHashEqualArtA[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedHashEqualArtA(name string, edges ...*HashEqual) {
	if a.Edges.namedHashEqualArtA == nil {
		a.Edges.namedHashEqualArtA = make(map[string][]*HashEqual)
	}
	if len(edges) == 0 {
		a.Edges.namedHashEqualArtA[name] = []*HashEqual{}
	} else {
		a.Edges.namedHashEqualArtA[name] = append(a.Edges.namedHashEqualArtA[name], edges...)
	}
}

// NamedHashEqualArtB returns the HashEqualArtB named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedHashEqualArtB(name string) ([]*HashEqual, error) {
	if a.Edges.namedHashEqualArtB == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedHashEqualArtB[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedHashEqualArtB(name string, edges ...*HashEqual) {
	if a.Edges.namedHashEqualArtB == nil {
		a.Edges.namedHashEqualArtB = make(map[string][]*HashEqual)
	}
	if len(edges) == 0 {
		a.Edges.namedHashEqualArtB[name] = []*HashEqual{}
	} else {
		a.Edges.namedHashEqualArtB[name] = append(a.Edges.namedHashEqualArtB[name], edges...)
	}
}

// NamedVex returns the Vex named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedVex(name string) ([]*CertifyVex, error) {
	if a.Edges.namedVex == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedVex[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedVex(name string, edges ...*CertifyVex) {
	if a.Edges.namedVex == nil {
		a.Edges.namedVex = make(map[string][]*CertifyVex)
	}
	if len(edges) == 0 {
		a.Edges.namedVex[name] = []*CertifyVex{}
	} else {
		a.Edges.namedVex[name] = append(a.Edges.namedVex[name], edges...)
	}
}

// NamedCertification returns the Certification named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedCertification(name string) ([]*Certification, error) {
	if a.Edges.namedCertification == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedCertification[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedCertification(name string, edges ...*Certification) {
	if a.Edges.namedCertification == nil {
		a.Edges.namedCertification = make(map[string][]*Certification)
	}
	if len(edges) == 0 {
		a.Edges.namedCertification[name] = []*Certification{}
	} else {
		a.Edges.namedCertification[name] = append(a.Edges.namedCertification[name], edges...)
	}
}

// NamedMetadata returns the Metadata named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedMetadata(name string) ([]*HasMetadata, error) {
	if a.Edges.namedMetadata == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedMetadata[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedMetadata(name string, edges ...*HasMetadata) {
	if a.Edges.namedMetadata == nil {
		a.Edges.namedMetadata = make(map[string][]*HasMetadata)
	}
	if len(edges) == 0 {
		a.Edges.namedMetadata[name] = []*HasMetadata{}
	} else {
		a.Edges.namedMetadata[name] = append(a.Edges.namedMetadata[name], edges...)
	}
}

// NamedPoc returns the Poc named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedPoc(name string) ([]*PointOfContact, error) {
	if a.Edges.namedPoc == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedPoc[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedPoc(name string, edges ...*PointOfContact) {
	if a.Edges.namedPoc == nil {
		a.Edges.namedPoc = make(map[string][]*PointOfContact)
	}
	if len(edges) == 0 {
		a.Edges.namedPoc[name] = []*PointOfContact{}
	} else {
		a.Edges.namedPoc[name] = append(a.Edges.namedPoc[name], edges...)
	}
}

// NamedIncludedInSboms returns the IncludedInSboms named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedIncludedInSboms(name string) ([]*BillOfMaterials, error) {
	if a.Edges.namedIncludedInSboms == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedIncludedInSboms[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedIncludedInSboms(name string, edges ...*BillOfMaterials) {
	if a.Edges.namedIncludedInSboms == nil {
		a.Edges.namedIncludedInSboms = make(map[string][]*BillOfMaterials)
	}
	if len(edges) == 0 {
		a.Edges.namedIncludedInSboms[name] = []*BillOfMaterials{}
	} else {
		a.Edges.namedIncludedInSboms[name] = append(a.Edges.namedIncludedInSboms[name], edges...)
	}
}

// Artifacts is a parsable slice of Artifact.
type Artifacts []*Artifact
