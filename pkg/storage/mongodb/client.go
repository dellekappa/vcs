/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultTimeout   = 15 * time.Second
	mongoHostMatcher = ``
)

type Client struct {
	client       *mongo.Client
	databaseName string
	timeout      time.Duration
	cosmos       bool
}

func New(connString string, databaseName string, opts ...ClientOpt) (*Client, error) {
	op := &clientOpts{
		timeout:  defaultTimeout,
		readPref: readpref.Nearest(),
	}

	for _, fn := range opts {
		fn(op)
	}

	mongoOpts := mongooptions.Client()
	mongoOpts.ApplyURI(connString)

	cons := writeconcern.Majority()
	cons.WTimeout = op.timeout

	mongoOpts.SetWriteConcern(cons)

	mongoOpts.ReadPreference = op.readPref

	if op.traceProvider != nil {
		mongoOpts.Monitor = otelmongo.NewMonitor(otelmongo.WithTracerProvider(op.traceProvider))
	}

	cosmos, err := detectCosmosConnectionString(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to detect cosmos MongoDB connection: %w", err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), op.timeout)
	defer cancel()

	client, err := mongo.Connect(ctxWithTimeout, mongoOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	return &Client{
		client:       client,
		databaseName: databaseName,
		cosmos:       cosmos,
		timeout:      op.timeout,
	}, nil
}

func (c *Client) Database() *mongo.Database {
	return c.client.Database(c.databaseName)
}

func (c *Client) ContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.timeout)
}

func (c *Client) Close() error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	err := c.client.Disconnect(ctxWithTimeout)
	if err != nil {
		if err.Error() == "client is disconnected" {
			return nil
		}

		return fmt.Errorf("failed to disconnect from MongoDB: %w", err)
	}

	return nil
}

func (c *Client) IsCosmos() bool {
	return c.cosmos
}

func (c *Client) NewExpirationIndex(fieldName string) mongo.IndexModel {
	var expSeconds int32 = 0
	if c.IsCosmos() {
		fieldName = "_ts"
		expSeconds = -1
	}

	return mongo.IndexModel{
		// cosmos _ts index https://learn.microsoft.com/en-us/azure/cosmos-db/mongodb/time-to-live
		// mongo ttl index https://www.mongodb.com/community/forums/t/ttl-index-internals/4086/2
		Keys: map[string]interface{}{
			fieldName: 1,
		},
		// expire at specific clock time in case of mongo
		// https://www.mongodb.com/docs/manual/tutorial/expire-data/#expire-documents-at-a-specific-clock-time
		Options: mongooptions.Index().SetExpireAfterSeconds(expSeconds),
	}
}

type clientOpts struct {
	timeout       time.Duration
	traceProvider trace.TracerProvider
	readPref      *readpref.ReadPref
}

type ClientOpt func(opts *clientOpts)

func WithTimeout(timeout time.Duration) ClientOpt {
	return func(opts *clientOpts) {
		opts.timeout = timeout
	}
}

func WithReadPref(pref *readpref.ReadPref) ClientOpt {
	return func(opts *clientOpts) {
		opts.readPref = pref
	}
}

func WithTraceProvider(traceProvider trace.TracerProvider) ClientOpt {
	return func(opts *clientOpts) {
		opts.traceProvider = traceProvider
	}
}

func detectCosmosConnectionString(connString string) (bool, error) {
	cs, err := connstring.Parse(connString)
	if err != nil {
		return false, err
	}
	for _, h := range cs.Hosts {
		hname := strings.Split(h, ":")[0]
		if strings.HasSuffix(hname, "cosmos.azure.com") || strings.HasSuffix(hname, "documents.azure.com") {
			return true, nil
		}
	}

	return false, nil
}
