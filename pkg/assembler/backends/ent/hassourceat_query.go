// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hassourceat"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
)

// HasSourceAtQuery is the builder for querying HasSourceAt entities.
type HasSourceAtQuery struct {
	config
	ctx                *QueryContext
	order              []hassourceat.OrderOption
	inters             []Interceptor
	predicates         []predicate.HasSourceAt
	withPackageVersion *PackageVersionQuery
	withAllVersions    *PackageNameQuery
	withSource         *SourceNameQuery
	modifiers          []func(*sql.Selector)
	loadTotal          []func(context.Context, []*HasSourceAt) error
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the HasSourceAtQuery builder.
func (hsaq *HasSourceAtQuery) Where(ps ...predicate.HasSourceAt) *HasSourceAtQuery {
	hsaq.predicates = append(hsaq.predicates, ps...)
	return hsaq
}

// Limit the number of records to be returned by this query.
func (hsaq *HasSourceAtQuery) Limit(limit int) *HasSourceAtQuery {
	hsaq.ctx.Limit = &limit
	return hsaq
}

// Offset to start from.
func (hsaq *HasSourceAtQuery) Offset(offset int) *HasSourceAtQuery {
	hsaq.ctx.Offset = &offset
	return hsaq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (hsaq *HasSourceAtQuery) Unique(unique bool) *HasSourceAtQuery {
	hsaq.ctx.Unique = &unique
	return hsaq
}

// Order specifies how the records should be ordered.
func (hsaq *HasSourceAtQuery) Order(o ...hassourceat.OrderOption) *HasSourceAtQuery {
	hsaq.order = append(hsaq.order, o...)
	return hsaq
}

// QueryPackageVersion chains the current query on the "package_version" edge.
func (hsaq *HasSourceAtQuery) QueryPackageVersion() *PackageVersionQuery {
	query := (&PackageVersionClient{config: hsaq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hsaq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hsaq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(hassourceat.Table, hassourceat.FieldID, selector),
			sqlgraph.To(packageversion.Table, packageversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, hassourceat.PackageVersionTable, hassourceat.PackageVersionColumn),
		)
		fromU = sqlgraph.SetNeighbors(hsaq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAllVersions chains the current query on the "all_versions" edge.
func (hsaq *HasSourceAtQuery) QueryAllVersions() *PackageNameQuery {
	query := (&PackageNameClient{config: hsaq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hsaq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hsaq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(hassourceat.Table, hassourceat.FieldID, selector),
			sqlgraph.To(packagename.Table, packagename.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, hassourceat.AllVersionsTable, hassourceat.AllVersionsColumn),
		)
		fromU = sqlgraph.SetNeighbors(hsaq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QuerySource chains the current query on the "source" edge.
func (hsaq *HasSourceAtQuery) QuerySource() *SourceNameQuery {
	query := (&SourceNameClient{config: hsaq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hsaq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hsaq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(hassourceat.Table, hassourceat.FieldID, selector),
			sqlgraph.To(sourcename.Table, sourcename.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, hassourceat.SourceTable, hassourceat.SourceColumn),
		)
		fromU = sqlgraph.SetNeighbors(hsaq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first HasSourceAt entity from the query.
// Returns a *NotFoundError when no HasSourceAt was found.
func (hsaq *HasSourceAtQuery) First(ctx context.Context) (*HasSourceAt, error) {
	nodes, err := hsaq.Limit(1).All(setContextOp(ctx, hsaq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{hassourceat.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) FirstX(ctx context.Context) *HasSourceAt {
	node, err := hsaq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first HasSourceAt ID from the query.
// Returns a *NotFoundError when no HasSourceAt ID was found.
func (hsaq *HasSourceAtQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = hsaq.Limit(1).IDs(setContextOp(ctx, hsaq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{hassourceat.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := hsaq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single HasSourceAt entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one HasSourceAt entity is found.
// Returns a *NotFoundError when no HasSourceAt entities are found.
func (hsaq *HasSourceAtQuery) Only(ctx context.Context) (*HasSourceAt, error) {
	nodes, err := hsaq.Limit(2).All(setContextOp(ctx, hsaq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{hassourceat.Label}
	default:
		return nil, &NotSingularError{hassourceat.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) OnlyX(ctx context.Context) *HasSourceAt {
	node, err := hsaq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only HasSourceAt ID in the query.
// Returns a *NotSingularError when more than one HasSourceAt ID is found.
// Returns a *NotFoundError when no entities are found.
func (hsaq *HasSourceAtQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = hsaq.Limit(2).IDs(setContextOp(ctx, hsaq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{hassourceat.Label}
	default:
		err = &NotSingularError{hassourceat.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := hsaq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of HasSourceAts.
func (hsaq *HasSourceAtQuery) All(ctx context.Context) ([]*HasSourceAt, error) {
	ctx = setContextOp(ctx, hsaq.ctx, ent.OpQueryAll)
	if err := hsaq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*HasSourceAt, *HasSourceAtQuery]()
	return withInterceptors[[]*HasSourceAt](ctx, hsaq, qr, hsaq.inters)
}

// AllX is like All, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) AllX(ctx context.Context) []*HasSourceAt {
	nodes, err := hsaq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of HasSourceAt IDs.
func (hsaq *HasSourceAtQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if hsaq.ctx.Unique == nil && hsaq.path != nil {
		hsaq.Unique(true)
	}
	ctx = setContextOp(ctx, hsaq.ctx, ent.OpQueryIDs)
	if err = hsaq.Select(hassourceat.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := hsaq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (hsaq *HasSourceAtQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, hsaq.ctx, ent.OpQueryCount)
	if err := hsaq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, hsaq, querierCount[*HasSourceAtQuery](), hsaq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) CountX(ctx context.Context) int {
	count, err := hsaq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (hsaq *HasSourceAtQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, hsaq.ctx, ent.OpQueryExist)
	switch _, err := hsaq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (hsaq *HasSourceAtQuery) ExistX(ctx context.Context) bool {
	exist, err := hsaq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the HasSourceAtQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (hsaq *HasSourceAtQuery) Clone() *HasSourceAtQuery {
	if hsaq == nil {
		return nil
	}
	return &HasSourceAtQuery{
		config:             hsaq.config,
		ctx:                hsaq.ctx.Clone(),
		order:              append([]hassourceat.OrderOption{}, hsaq.order...),
		inters:             append([]Interceptor{}, hsaq.inters...),
		predicates:         append([]predicate.HasSourceAt{}, hsaq.predicates...),
		withPackageVersion: hsaq.withPackageVersion.Clone(),
		withAllVersions:    hsaq.withAllVersions.Clone(),
		withSource:         hsaq.withSource.Clone(),
		// clone intermediate query.
		sql:  hsaq.sql.Clone(),
		path: hsaq.path,
	}
}

// WithPackageVersion tells the query-builder to eager-load the nodes that are connected to
// the "package_version" edge. The optional arguments are used to configure the query builder of the edge.
func (hsaq *HasSourceAtQuery) WithPackageVersion(opts ...func(*PackageVersionQuery)) *HasSourceAtQuery {
	query := (&PackageVersionClient{config: hsaq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	hsaq.withPackageVersion = query
	return hsaq
}

// WithAllVersions tells the query-builder to eager-load the nodes that are connected to
// the "all_versions" edge. The optional arguments are used to configure the query builder of the edge.
func (hsaq *HasSourceAtQuery) WithAllVersions(opts ...func(*PackageNameQuery)) *HasSourceAtQuery {
	query := (&PackageNameClient{config: hsaq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	hsaq.withAllVersions = query
	return hsaq
}

// WithSource tells the query-builder to eager-load the nodes that are connected to
// the "source" edge. The optional arguments are used to configure the query builder of the edge.
func (hsaq *HasSourceAtQuery) WithSource(opts ...func(*SourceNameQuery)) *HasSourceAtQuery {
	query := (&SourceNameClient{config: hsaq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	hsaq.withSource = query
	return hsaq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		PackageVersionID uuid.UUID `json:"package_version_id,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.HasSourceAt.Query().
//		GroupBy(hassourceat.FieldPackageVersionID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (hsaq *HasSourceAtQuery) GroupBy(field string, fields ...string) *HasSourceAtGroupBy {
	hsaq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &HasSourceAtGroupBy{build: hsaq}
	grbuild.flds = &hsaq.ctx.Fields
	grbuild.label = hassourceat.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		PackageVersionID uuid.UUID `json:"package_version_id,omitempty"`
//	}
//
//	client.HasSourceAt.Query().
//		Select(hassourceat.FieldPackageVersionID).
//		Scan(ctx, &v)
func (hsaq *HasSourceAtQuery) Select(fields ...string) *HasSourceAtSelect {
	hsaq.ctx.Fields = append(hsaq.ctx.Fields, fields...)
	sbuild := &HasSourceAtSelect{HasSourceAtQuery: hsaq}
	sbuild.label = hassourceat.Label
	sbuild.flds, sbuild.scan = &hsaq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a HasSourceAtSelect configured with the given aggregations.
func (hsaq *HasSourceAtQuery) Aggregate(fns ...AggregateFunc) *HasSourceAtSelect {
	return hsaq.Select().Aggregate(fns...)
}

func (hsaq *HasSourceAtQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range hsaq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, hsaq); err != nil {
				return err
			}
		}
	}
	for _, f := range hsaq.ctx.Fields {
		if !hassourceat.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if hsaq.path != nil {
		prev, err := hsaq.path(ctx)
		if err != nil {
			return err
		}
		hsaq.sql = prev
	}
	return nil
}

func (hsaq *HasSourceAtQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*HasSourceAt, error) {
	var (
		nodes       = []*HasSourceAt{}
		_spec       = hsaq.querySpec()
		loadedTypes = [3]bool{
			hsaq.withPackageVersion != nil,
			hsaq.withAllVersions != nil,
			hsaq.withSource != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*HasSourceAt).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &HasSourceAt{config: hsaq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(hsaq.modifiers) > 0 {
		_spec.Modifiers = hsaq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, hsaq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := hsaq.withPackageVersion; query != nil {
		if err := hsaq.loadPackageVersion(ctx, query, nodes, nil,
			func(n *HasSourceAt, e *PackageVersion) { n.Edges.PackageVersion = e }); err != nil {
			return nil, err
		}
	}
	if query := hsaq.withAllVersions; query != nil {
		if err := hsaq.loadAllVersions(ctx, query, nodes, nil,
			func(n *HasSourceAt, e *PackageName) { n.Edges.AllVersions = e }); err != nil {
			return nil, err
		}
	}
	if query := hsaq.withSource; query != nil {
		if err := hsaq.loadSource(ctx, query, nodes, nil,
			func(n *HasSourceAt, e *SourceName) { n.Edges.Source = e }); err != nil {
			return nil, err
		}
	}
	for i := range hsaq.loadTotal {
		if err := hsaq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (hsaq *HasSourceAtQuery) loadPackageVersion(ctx context.Context, query *PackageVersionQuery, nodes []*HasSourceAt, init func(*HasSourceAt), assign func(*HasSourceAt, *PackageVersion)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*HasSourceAt)
	for i := range nodes {
		if nodes[i].PackageVersionID == nil {
			continue
		}
		fk := *nodes[i].PackageVersionID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(packageversion.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "package_version_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (hsaq *HasSourceAtQuery) loadAllVersions(ctx context.Context, query *PackageNameQuery, nodes []*HasSourceAt, init func(*HasSourceAt), assign func(*HasSourceAt, *PackageName)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*HasSourceAt)
	for i := range nodes {
		if nodes[i].PackageNameID == nil {
			continue
		}
		fk := *nodes[i].PackageNameID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(packagename.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "package_name_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (hsaq *HasSourceAtQuery) loadSource(ctx context.Context, query *SourceNameQuery, nodes []*HasSourceAt, init func(*HasSourceAt), assign func(*HasSourceAt, *SourceName)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*HasSourceAt)
	for i := range nodes {
		fk := nodes[i].SourceID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(sourcename.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "source_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (hsaq *HasSourceAtQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := hsaq.querySpec()
	if len(hsaq.modifiers) > 0 {
		_spec.Modifiers = hsaq.modifiers
	}
	_spec.Node.Columns = hsaq.ctx.Fields
	if len(hsaq.ctx.Fields) > 0 {
		_spec.Unique = hsaq.ctx.Unique != nil && *hsaq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, hsaq.driver, _spec)
}

func (hsaq *HasSourceAtQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(hassourceat.Table, hassourceat.Columns, sqlgraph.NewFieldSpec(hassourceat.FieldID, field.TypeUUID))
	_spec.From = hsaq.sql
	if unique := hsaq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if hsaq.path != nil {
		_spec.Unique = true
	}
	if fields := hsaq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, hassourceat.FieldID)
		for i := range fields {
			if fields[i] != hassourceat.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if hsaq.withPackageVersion != nil {
			_spec.Node.AddColumnOnce(hassourceat.FieldPackageVersionID)
		}
		if hsaq.withAllVersions != nil {
			_spec.Node.AddColumnOnce(hassourceat.FieldPackageNameID)
		}
		if hsaq.withSource != nil {
			_spec.Node.AddColumnOnce(hassourceat.FieldSourceID)
		}
	}
	if ps := hsaq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := hsaq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := hsaq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := hsaq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (hsaq *HasSourceAtQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(hsaq.driver.Dialect())
	t1 := builder.Table(hassourceat.Table)
	columns := hsaq.ctx.Fields
	if len(columns) == 0 {
		columns = hassourceat.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if hsaq.sql != nil {
		selector = hsaq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if hsaq.ctx.Unique != nil && *hsaq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range hsaq.predicates {
		p(selector)
	}
	for _, p := range hsaq.order {
		p(selector)
	}
	if offset := hsaq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := hsaq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// HasSourceAtGroupBy is the group-by builder for HasSourceAt entities.
type HasSourceAtGroupBy struct {
	selector
	build *HasSourceAtQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (hsagb *HasSourceAtGroupBy) Aggregate(fns ...AggregateFunc) *HasSourceAtGroupBy {
	hsagb.fns = append(hsagb.fns, fns...)
	return hsagb
}

// Scan applies the selector query and scans the result into the given value.
func (hsagb *HasSourceAtGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, hsagb.build.ctx, ent.OpQueryGroupBy)
	if err := hsagb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*HasSourceAtQuery, *HasSourceAtGroupBy](ctx, hsagb.build, hsagb, hsagb.build.inters, v)
}

func (hsagb *HasSourceAtGroupBy) sqlScan(ctx context.Context, root *HasSourceAtQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(hsagb.fns))
	for _, fn := range hsagb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*hsagb.flds)+len(hsagb.fns))
		for _, f := range *hsagb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*hsagb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := hsagb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// HasSourceAtSelect is the builder for selecting fields of HasSourceAt entities.
type HasSourceAtSelect struct {
	*HasSourceAtQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (hsas *HasSourceAtSelect) Aggregate(fns ...AggregateFunc) *HasSourceAtSelect {
	hsas.fns = append(hsas.fns, fns...)
	return hsas
}

// Scan applies the selector query and scans the result into the given value.
func (hsas *HasSourceAtSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, hsas.ctx, ent.OpQuerySelect)
	if err := hsas.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*HasSourceAtQuery, *HasSourceAtSelect](ctx, hsas.HasSourceAtQuery, hsas, hsas.inters, v)
}

func (hsas *HasSourceAtSelect) sqlScan(ctx context.Context, root *HasSourceAtQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(hsas.fns))
	for _, fn := range hsas.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*hsas.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := hsas.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
