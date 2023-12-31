// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/kubuskotak/king/pkg/persist/crud/ent/migrate"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/application"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/article"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/index"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/user"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/ymir"
)

// Client is the client that holds all ent builders.
type Client struct {
	config
	// Schema is the client for creating, migrating and dropping schema.
	Schema *migrate.Schema
	// Application is the client for interacting with the Application builders.
	Application *ApplicationClient
	// Article is the client for interacting with the Article builders.
	Article *ArticleClient
	// Index is the client for interacting with the Index builders.
	Index *IndexClient
	// User is the client for interacting with the User builders.
	User *UserClient
	// Ymir is the client for interacting with the Ymir builders.
	Ymir *YmirClient
}

// NewClient creates a new client configured with the given options.
func NewClient(opts ...Option) *Client {
	cfg := config{log: log.Println, hooks: &hooks{}, inters: &inters{}}
	cfg.options(opts...)
	client := &Client{config: cfg}
	client.init()
	return client
}

func (c *Client) init() {
	c.Schema = migrate.NewSchema(c.driver)
	c.Application = NewApplicationClient(c.config)
	c.Article = NewArticleClient(c.config)
	c.Index = NewIndexClient(c.config)
	c.User = NewUserClient(c.config)
	c.Ymir = NewYmirClient(c.config)
}

type (
	// config is the configuration for the client and its builder.
	config struct {
		// driver used for executing database requests.
		driver dialect.Driver
		// debug enable a debug logging.
		debug bool
		// log used for logging on debug mode.
		log func(...any)
		// hooks to execute on mutations.
		hooks *hooks
		// interceptors to execute on queries.
		inters *inters
	}
	// Option function to configure the client.
	Option func(*config)
)

// options applies the options on the config object.
func (c *config) options(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
	if c.debug {
		c.driver = dialect.Debug(c.driver, c.log)
	}
}

// Debug enables debug logging on the ent.Driver.
func Debug() Option {
	return func(c *config) {
		c.debug = true
	}
}

// Log sets the logging function for debug mode.
func Log(fn func(...any)) Option {
	return func(c *config) {
		c.log = fn
	}
}

// Driver configures the client driver.
func Driver(driver dialect.Driver) Option {
	return func(c *config) {
		c.driver = driver
	}
}

// Open opens a database/sql.DB specified by the driver name and
// the data source name, and returns a new client attached to it.
// Optional parameters can be added for configuring the client.
func Open(driverName, dataSourceName string, options ...Option) (*Client, error) {
	switch driverName {
	case dialect.MySQL, dialect.Postgres, dialect.SQLite:
		drv, err := sql.Open(driverName, dataSourceName)
		if err != nil {
			return nil, err
		}
		return NewClient(append(options, Driver(drv))...), nil
	default:
		return nil, fmt.Errorf("unsupported driver: %q", driverName)
	}
}

// Tx returns a new transactional client. The provided context
// is used until the transaction is committed or rolled back.
func (c *Client) Tx(ctx context.Context) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := newTx(ctx, c.driver)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = tx
	return &Tx{
		ctx:         ctx,
		config:      cfg,
		Application: NewApplicationClient(cfg),
		Article:     NewArticleClient(cfg),
		Index:       NewIndexClient(cfg),
		User:        NewUserClient(cfg),
		Ymir:        NewYmirClient(cfg),
	}, nil
}

// BeginTx returns a transactional client with specified options.
func (c *Client) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := c.driver.(interface {
		BeginTx(context.Context, *sql.TxOptions) (dialect.Tx, error)
	}).BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = &txDriver{tx: tx, drv: c.driver}
	return &Tx{
		ctx:         ctx,
		config:      cfg,
		Application: NewApplicationClient(cfg),
		Article:     NewArticleClient(cfg),
		Index:       NewIndexClient(cfg),
		User:        NewUserClient(cfg),
		Ymir:        NewYmirClient(cfg),
	}, nil
}

// Debug returns a new debug-client. It's used to get verbose logging on specific operations.
//
//	client.Debug().
//		Application.
//		Query().
//		Count(ctx)
func (c *Client) Debug() *Client {
	if c.debug {
		return c
	}
	cfg := c.config
	cfg.driver = dialect.Debug(c.driver, c.log)
	client := &Client{config: cfg}
	client.init()
	return client
}

// Close closes the database connection and prevents new queries from starting.
func (c *Client) Close() error {
	return c.driver.Close()
}

// Use adds the mutation hooks to all the entity clients.
// In order to add hooks to a specific client, call: `client.Node.Use(...)`.
func (c *Client) Use(hooks ...Hook) {
	c.Application.Use(hooks...)
	c.Article.Use(hooks...)
	c.Index.Use(hooks...)
	c.User.Use(hooks...)
	c.Ymir.Use(hooks...)
}

// Intercept adds the query interceptors to all the entity clients.
// In order to add interceptors to a specific client, call: `client.Node.Intercept(...)`.
func (c *Client) Intercept(interceptors ...Interceptor) {
	c.Application.Intercept(interceptors...)
	c.Article.Intercept(interceptors...)
	c.Index.Intercept(interceptors...)
	c.User.Intercept(interceptors...)
	c.Ymir.Intercept(interceptors...)
}

// Mutate implements the ent.Mutator interface.
func (c *Client) Mutate(ctx context.Context, m Mutation) (Value, error) {
	switch m := m.(type) {
	case *ApplicationMutation:
		return c.Application.mutate(ctx, m)
	case *ArticleMutation:
		return c.Article.mutate(ctx, m)
	case *IndexMutation:
		return c.Index.mutate(ctx, m)
	case *UserMutation:
		return c.User.mutate(ctx, m)
	case *YmirMutation:
		return c.Ymir.mutate(ctx, m)
	default:
		return nil, fmt.Errorf("ent: unknown mutation type %T", m)
	}
}

// ApplicationClient is a client for the Application schema.
type ApplicationClient struct {
	config
}

// NewApplicationClient returns a client for the Application from the given config.
func NewApplicationClient(c config) *ApplicationClient {
	return &ApplicationClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `application.Hooks(f(g(h())))`.
func (c *ApplicationClient) Use(hooks ...Hook) {
	c.hooks.Application = append(c.hooks.Application, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `application.Intercept(f(g(h())))`.
func (c *ApplicationClient) Intercept(interceptors ...Interceptor) {
	c.inters.Application = append(c.inters.Application, interceptors...)
}

// Create returns a builder for creating a Application entity.
func (c *ApplicationClient) Create() *ApplicationCreate {
	mutation := newApplicationMutation(c.config, OpCreate)
	return &ApplicationCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Application entities.
func (c *ApplicationClient) CreateBulk(builders ...*ApplicationCreate) *ApplicationCreateBulk {
	return &ApplicationCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Application.
func (c *ApplicationClient) Update() *ApplicationUpdate {
	mutation := newApplicationMutation(c.config, OpUpdate)
	return &ApplicationUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *ApplicationClient) UpdateOne(a *Application) *ApplicationUpdateOne {
	mutation := newApplicationMutation(c.config, OpUpdateOne, withApplication(a))
	return &ApplicationUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *ApplicationClient) UpdateOneID(id string) *ApplicationUpdateOne {
	mutation := newApplicationMutation(c.config, OpUpdateOne, withApplicationID(id))
	return &ApplicationUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Application.
func (c *ApplicationClient) Delete() *ApplicationDelete {
	mutation := newApplicationMutation(c.config, OpDelete)
	return &ApplicationDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *ApplicationClient) DeleteOne(a *Application) *ApplicationDeleteOne {
	return c.DeleteOneID(a.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *ApplicationClient) DeleteOneID(id string) *ApplicationDeleteOne {
	builder := c.Delete().Where(application.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &ApplicationDeleteOne{builder}
}

// Query returns a query builder for Application.
func (c *ApplicationClient) Query() *ApplicationQuery {
	return &ApplicationQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeApplication},
		inters: c.Interceptors(),
	}
}

// Get returns a Application entity by its id.
func (c *ApplicationClient) Get(ctx context.Context, id string) (*Application, error) {
	return c.Query().Where(application.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *ApplicationClient) GetX(ctx context.Context, id string) *Application {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryUser queries the user edge of a Application.
func (c *ApplicationClient) QueryUser(a *Application) *UserQuery {
	query := (&UserClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(application.Table, application.FieldID, id),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, application.UserTable, application.UserColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryIndexes queries the indexes edge of a Application.
func (c *ApplicationClient) QueryIndexes(a *Application) *IndexQuery {
	query := (&IndexClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(application.Table, application.FieldID, id),
			sqlgraph.To(index.Table, index.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, application.IndexesTable, application.IndexesColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *ApplicationClient) Hooks() []Hook {
	return c.hooks.Application
}

// Interceptors returns the client interceptors.
func (c *ApplicationClient) Interceptors() []Interceptor {
	return c.inters.Application
}

func (c *ApplicationClient) mutate(ctx context.Context, m *ApplicationMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&ApplicationCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&ApplicationUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&ApplicationUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&ApplicationDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown Application mutation op: %q", m.Op())
	}
}

// ArticleClient is a client for the Article schema.
type ArticleClient struct {
	config
}

// NewArticleClient returns a client for the Article from the given config.
func NewArticleClient(c config) *ArticleClient {
	return &ArticleClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `article.Hooks(f(g(h())))`.
func (c *ArticleClient) Use(hooks ...Hook) {
	c.hooks.Article = append(c.hooks.Article, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `article.Intercept(f(g(h())))`.
func (c *ArticleClient) Intercept(interceptors ...Interceptor) {
	c.inters.Article = append(c.inters.Article, interceptors...)
}

// Create returns a builder for creating a Article entity.
func (c *ArticleClient) Create() *ArticleCreate {
	mutation := newArticleMutation(c.config, OpCreate)
	return &ArticleCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Article entities.
func (c *ArticleClient) CreateBulk(builders ...*ArticleCreate) *ArticleCreateBulk {
	return &ArticleCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Article.
func (c *ArticleClient) Update() *ArticleUpdate {
	mutation := newArticleMutation(c.config, OpUpdate)
	return &ArticleUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *ArticleClient) UpdateOne(a *Article) *ArticleUpdateOne {
	mutation := newArticleMutation(c.config, OpUpdateOne, withArticle(a))
	return &ArticleUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *ArticleClient) UpdateOneID(id int) *ArticleUpdateOne {
	mutation := newArticleMutation(c.config, OpUpdateOne, withArticleID(id))
	return &ArticleUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Article.
func (c *ArticleClient) Delete() *ArticleDelete {
	mutation := newArticleMutation(c.config, OpDelete)
	return &ArticleDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *ArticleClient) DeleteOne(a *Article) *ArticleDeleteOne {
	return c.DeleteOneID(a.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *ArticleClient) DeleteOneID(id int) *ArticleDeleteOne {
	builder := c.Delete().Where(article.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &ArticleDeleteOne{builder}
}

// Query returns a query builder for Article.
func (c *ArticleClient) Query() *ArticleQuery {
	return &ArticleQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeArticle},
		inters: c.Interceptors(),
	}
}

// Get returns a Article entity by its id.
func (c *ArticleClient) Get(ctx context.Context, id int) (*Article, error) {
	return c.Query().Where(article.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *ArticleClient) GetX(ctx context.Context, id int) *Article {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// Hooks returns the client hooks.
func (c *ArticleClient) Hooks() []Hook {
	return c.hooks.Article
}

// Interceptors returns the client interceptors.
func (c *ArticleClient) Interceptors() []Interceptor {
	return c.inters.Article
}

func (c *ArticleClient) mutate(ctx context.Context, m *ArticleMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&ArticleCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&ArticleUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&ArticleUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&ArticleDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown Article mutation op: %q", m.Op())
	}
}

// IndexClient is a client for the Index schema.
type IndexClient struct {
	config
}

// NewIndexClient returns a client for the Index from the given config.
func NewIndexClient(c config) *IndexClient {
	return &IndexClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `index.Hooks(f(g(h())))`.
func (c *IndexClient) Use(hooks ...Hook) {
	c.hooks.Index = append(c.hooks.Index, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `index.Intercept(f(g(h())))`.
func (c *IndexClient) Intercept(interceptors ...Interceptor) {
	c.inters.Index = append(c.inters.Index, interceptors...)
}

// Create returns a builder for creating a Index entity.
func (c *IndexClient) Create() *IndexCreate {
	mutation := newIndexMutation(c.config, OpCreate)
	return &IndexCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Index entities.
func (c *IndexClient) CreateBulk(builders ...*IndexCreate) *IndexCreateBulk {
	return &IndexCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Index.
func (c *IndexClient) Update() *IndexUpdate {
	mutation := newIndexMutation(c.config, OpUpdate)
	return &IndexUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *IndexClient) UpdateOne(i *Index) *IndexUpdateOne {
	mutation := newIndexMutation(c.config, OpUpdateOne, withIndex(i))
	return &IndexUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *IndexClient) UpdateOneID(id int) *IndexUpdateOne {
	mutation := newIndexMutation(c.config, OpUpdateOne, withIndexID(id))
	return &IndexUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Index.
func (c *IndexClient) Delete() *IndexDelete {
	mutation := newIndexMutation(c.config, OpDelete)
	return &IndexDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *IndexClient) DeleteOne(i *Index) *IndexDeleteOne {
	return c.DeleteOneID(i.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *IndexClient) DeleteOneID(id int) *IndexDeleteOne {
	builder := c.Delete().Where(index.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &IndexDeleteOne{builder}
}

// Query returns a query builder for Index.
func (c *IndexClient) Query() *IndexQuery {
	return &IndexQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeIndex},
		inters: c.Interceptors(),
	}
}

// Get returns a Index entity by its id.
func (c *IndexClient) Get(ctx context.Context, id int) (*Index, error) {
	return c.Query().Where(index.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *IndexClient) GetX(ctx context.Context, id int) *Index {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryApplication queries the application edge of a Index.
func (c *IndexClient) QueryApplication(i *Index) *ApplicationQuery {
	query := (&ApplicationClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := i.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(index.Table, index.FieldID, id),
			sqlgraph.To(application.Table, application.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, index.ApplicationTable, index.ApplicationColumn),
		)
		fromV = sqlgraph.Neighbors(i.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *IndexClient) Hooks() []Hook {
	return c.hooks.Index
}

// Interceptors returns the client interceptors.
func (c *IndexClient) Interceptors() []Interceptor {
	return c.inters.Index
}

func (c *IndexClient) mutate(ctx context.Context, m *IndexMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&IndexCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&IndexUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&IndexUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&IndexDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown Index mutation op: %q", m.Op())
	}
}

// UserClient is a client for the User schema.
type UserClient struct {
	config
}

// NewUserClient returns a client for the User from the given config.
func NewUserClient(c config) *UserClient {
	return &UserClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `user.Hooks(f(g(h())))`.
func (c *UserClient) Use(hooks ...Hook) {
	c.hooks.User = append(c.hooks.User, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `user.Intercept(f(g(h())))`.
func (c *UserClient) Intercept(interceptors ...Interceptor) {
	c.inters.User = append(c.inters.User, interceptors...)
}

// Create returns a builder for creating a User entity.
func (c *UserClient) Create() *UserCreate {
	mutation := newUserMutation(c.config, OpCreate)
	return &UserCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of User entities.
func (c *UserClient) CreateBulk(builders ...*UserCreate) *UserCreateBulk {
	return &UserCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for User.
func (c *UserClient) Update() *UserUpdate {
	mutation := newUserMutation(c.config, OpUpdate)
	return &UserUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *UserClient) UpdateOne(u *User) *UserUpdateOne {
	mutation := newUserMutation(c.config, OpUpdateOne, withUser(u))
	return &UserUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *UserClient) UpdateOneID(id int) *UserUpdateOne {
	mutation := newUserMutation(c.config, OpUpdateOne, withUserID(id))
	return &UserUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for User.
func (c *UserClient) Delete() *UserDelete {
	mutation := newUserMutation(c.config, OpDelete)
	return &UserDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *UserClient) DeleteOne(u *User) *UserDeleteOne {
	return c.DeleteOneID(u.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *UserClient) DeleteOneID(id int) *UserDeleteOne {
	builder := c.Delete().Where(user.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &UserDeleteOne{builder}
}

// Query returns a query builder for User.
func (c *UserClient) Query() *UserQuery {
	return &UserQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeUser},
		inters: c.Interceptors(),
	}
}

// Get returns a User entity by its id.
func (c *UserClient) Get(ctx context.Context, id int) (*User, error) {
	return c.Query().Where(user.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *UserClient) GetX(ctx context.Context, id int) *User {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryApplications queries the applications edge of a User.
func (c *UserClient) QueryApplications(u *User) *ApplicationQuery {
	query := (&ApplicationClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := u.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(user.Table, user.FieldID, id),
			sqlgraph.To(application.Table, application.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, user.ApplicationsTable, user.ApplicationsColumn),
		)
		fromV = sqlgraph.Neighbors(u.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *UserClient) Hooks() []Hook {
	return c.hooks.User
}

// Interceptors returns the client interceptors.
func (c *UserClient) Interceptors() []Interceptor {
	return c.inters.User
}

func (c *UserClient) mutate(ctx context.Context, m *UserMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&UserCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&UserUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&UserUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&UserDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown User mutation op: %q", m.Op())
	}
}

// YmirClient is a client for the Ymir schema.
type YmirClient struct {
	config
}

// NewYmirClient returns a client for the Ymir from the given config.
func NewYmirClient(c config) *YmirClient {
	return &YmirClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `ymir.Hooks(f(g(h())))`.
func (c *YmirClient) Use(hooks ...Hook) {
	c.hooks.Ymir = append(c.hooks.Ymir, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `ymir.Intercept(f(g(h())))`.
func (c *YmirClient) Intercept(interceptors ...Interceptor) {
	c.inters.Ymir = append(c.inters.Ymir, interceptors...)
}

// Create returns a builder for creating a Ymir entity.
func (c *YmirClient) Create() *YmirCreate {
	mutation := newYmirMutation(c.config, OpCreate)
	return &YmirCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Ymir entities.
func (c *YmirClient) CreateBulk(builders ...*YmirCreate) *YmirCreateBulk {
	return &YmirCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Ymir.
func (c *YmirClient) Update() *YmirUpdate {
	mutation := newYmirMutation(c.config, OpUpdate)
	return &YmirUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *YmirClient) UpdateOne(y *Ymir) *YmirUpdateOne {
	mutation := newYmirMutation(c.config, OpUpdateOne, withYmir(y))
	return &YmirUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *YmirClient) UpdateOneID(id int) *YmirUpdateOne {
	mutation := newYmirMutation(c.config, OpUpdateOne, withYmirID(id))
	return &YmirUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Ymir.
func (c *YmirClient) Delete() *YmirDelete {
	mutation := newYmirMutation(c.config, OpDelete)
	return &YmirDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *YmirClient) DeleteOne(y *Ymir) *YmirDeleteOne {
	return c.DeleteOneID(y.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *YmirClient) DeleteOneID(id int) *YmirDeleteOne {
	builder := c.Delete().Where(ymir.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &YmirDeleteOne{builder}
}

// Query returns a query builder for Ymir.
func (c *YmirClient) Query() *YmirQuery {
	return &YmirQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeYmir},
		inters: c.Interceptors(),
	}
}

// Get returns a Ymir entity by its id.
func (c *YmirClient) Get(ctx context.Context, id int) (*Ymir, error) {
	return c.Query().Where(ymir.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *YmirClient) GetX(ctx context.Context, id int) *Ymir {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// Hooks returns the client hooks.
func (c *YmirClient) Hooks() []Hook {
	return c.hooks.Ymir
}

// Interceptors returns the client interceptors.
func (c *YmirClient) Interceptors() []Interceptor {
	return c.inters.Ymir
}

func (c *YmirClient) mutate(ctx context.Context, m *YmirMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&YmirCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&YmirUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&YmirUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&YmirDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown Ymir mutation op: %q", m.Op())
	}
}

// hooks and interceptors per client, for fast access.
type (
	hooks struct {
		Application, Article, Index, User, Ymir []ent.Hook
	}
	inters struct {
		Application, Article, Index, User, Ymir []ent.Interceptor
	}
)
