// Code generated by ent, DO NOT EDIT.

package packagename

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the packagename type in the database.
	Label = "package_name"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldType holds the string denoting the type field in the database.
	FieldType = "type"
	// FieldNamespace holds the string denoting the namespace field in the database.
	FieldNamespace = "namespace"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// EdgeVersions holds the string denoting the versions edge name in mutations.
	EdgeVersions = "versions"
	// EdgeHasSourceAt holds the string denoting the has_source_at edge name in mutations.
	EdgeHasSourceAt = "has_source_at"
	// EdgeCertification holds the string denoting the certification edge name in mutations.
	EdgeCertification = "certification"
	// EdgeMetadata holds the string denoting the metadata edge name in mutations.
	EdgeMetadata = "metadata"
	// EdgePoc holds the string denoting the poc edge name in mutations.
	EdgePoc = "poc"
	// Table holds the table name of the packagename in the database.
	Table = "package_names"
	// VersionsTable is the table that holds the versions relation/edge.
	VersionsTable = "package_versions"
	// VersionsInverseTable is the table name for the PackageVersion entity.
	// It exists in this package in order to avoid circular dependency with the "packageversion" package.
	VersionsInverseTable = "package_versions"
	// VersionsColumn is the table column denoting the versions relation/edge.
	VersionsColumn = "name_id"
	// HasSourceAtTable is the table that holds the has_source_at relation/edge.
	HasSourceAtTable = "has_source_ats"
	// HasSourceAtInverseTable is the table name for the HasSourceAt entity.
	// It exists in this package in order to avoid circular dependency with the "hassourceat" package.
	HasSourceAtInverseTable = "has_source_ats"
	// HasSourceAtColumn is the table column denoting the has_source_at relation/edge.
	HasSourceAtColumn = "package_name_id"
	// CertificationTable is the table that holds the certification relation/edge.
	CertificationTable = "certifications"
	// CertificationInverseTable is the table name for the Certification entity.
	// It exists in this package in order to avoid circular dependency with the "certification" package.
	CertificationInverseTable = "certifications"
	// CertificationColumn is the table column denoting the certification relation/edge.
	CertificationColumn = "package_name_id"
	// MetadataTable is the table that holds the metadata relation/edge.
	MetadataTable = "has_metadata"
	// MetadataInverseTable is the table name for the HasMetadata entity.
	// It exists in this package in order to avoid circular dependency with the "hasmetadata" package.
	MetadataInverseTable = "has_metadata"
	// MetadataColumn is the table column denoting the metadata relation/edge.
	MetadataColumn = "package_name_id"
	// PocTable is the table that holds the poc relation/edge.
	PocTable = "point_of_contacts"
	// PocInverseTable is the table name for the PointOfContact entity.
	// It exists in this package in order to avoid circular dependency with the "pointofcontact" package.
	PocInverseTable = "point_of_contacts"
	// PocColumn is the table column denoting the poc relation/edge.
	PocColumn = "package_name_id"
)

// Columns holds all SQL columns for packagename fields.
var Columns = []string{
	FieldID,
	FieldType,
	FieldNamespace,
	FieldName,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// TypeValidator is a validator for the "type" field. It is called by the builders before save.
	TypeValidator func(string) error
	// NameValidator is a validator for the "name" field. It is called by the builders before save.
	NameValidator func(string) error
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// OrderOption defines the ordering options for the PackageName queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByType orders the results by the type field.
func ByType(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldType, opts...).ToFunc()
}

// ByNamespace orders the results by the namespace field.
func ByNamespace(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldNamespace, opts...).ToFunc()
}

// ByName orders the results by the name field.
func ByName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldName, opts...).ToFunc()
}

// ByVersionsCount orders the results by versions count.
func ByVersionsCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newVersionsStep(), opts...)
	}
}

// ByVersions orders the results by versions terms.
func ByVersions(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newVersionsStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByHasSourceAtCount orders the results by has_source_at count.
func ByHasSourceAtCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newHasSourceAtStep(), opts...)
	}
}

// ByHasSourceAt orders the results by has_source_at terms.
func ByHasSourceAt(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newHasSourceAtStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByCertificationCount orders the results by certification count.
func ByCertificationCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newCertificationStep(), opts...)
	}
}

// ByCertification orders the results by certification terms.
func ByCertification(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newCertificationStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByMetadataCount orders the results by metadata count.
func ByMetadataCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newMetadataStep(), opts...)
	}
}

// ByMetadata orders the results by metadata terms.
func ByMetadata(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newMetadataStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByPocCount orders the results by poc count.
func ByPocCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newPocStep(), opts...)
	}
}

// ByPoc orders the results by poc terms.
func ByPoc(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newPocStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newVersionsStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(VersionsInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, false, VersionsTable, VersionsColumn),
	)
}
func newHasSourceAtStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(HasSourceAtInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, true, HasSourceAtTable, HasSourceAtColumn),
	)
}
func newCertificationStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(CertificationInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, true, CertificationTable, CertificationColumn),
	)
}
func newMetadataStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(MetadataInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, true, MetadataTable, MetadataColumn),
	)
}
func newPocStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(PocInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, true, PocTable, PocColumn),
	)
}
