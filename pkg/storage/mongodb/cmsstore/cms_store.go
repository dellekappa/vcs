/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmsstore

import (
	"errors"
	"fmt"
	cmsapi "github.com/dellekappa/kcms-go/spi/cms"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Store provides local KMS storage using mongodb.
type Store struct {
	client *mongodb.Client
}

const (
	cmsStoreName = "cms_store"
)

// NewStore initializes a Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{client: mongoClient}
}

type dataWrapper struct {
	ID  string `bson:"_id"`
	Bin []byte `bson:"bin,omitempty"`
}

// Put stores the given cert under the given certID. Overwrites silently.
func (s *Store) Put(certID string, key []byte) error {
	coll := s.client.Database().Collection(cmsStoreName)

	ctx, cancel := s.client.ContextWithTimeout()
	defer cancel()

	_, err := coll.UpdateByID(ctx, certID, bson.M{
		"$set": &dataWrapper{
			ID:  certID,
			Bin: key,
		},
	}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}

	return nil
}

// Get retrieves the cert stored under the given certID. If no cert is found,
// the returned error is expected to wrap ErrCertNotFound. CMS implementations
// may check to see if the error wraps that error type for certain operations.
func (s *Store) Get(certID string) ([]byte, error) {
	coll := s.client.Database().Collection(cmsStoreName)

	ctx, cancel := s.client.ContextWithTimeout()
	defer cancel()

	result := &dataWrapper{}

	err := coll.FindOne(ctx, bson.M{"_id": certID}).Decode(result)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("%w. Underlying error: %s",
			cmsapi.ErrCertNotFound, err.Error())
	}

	if err != nil {
		return nil, err
	}

	return result.Bin, nil
}

// Delete deletes the cert stored under the given certID. A CertManager will
// assume that attempting to delete a non-existent key will not return an error.
func (s *Store) Delete(certID string) error {
	coll := s.client.Database().Collection(cmsStoreName)

	ctx, cancel := s.client.ContextWithTimeout()
	defer cancel()

	_, err := coll.DeleteOne(ctx, bson.M{"_id": certID})
	if err != nil {
		return fmt.Errorf("failed to run DeleteOne command in MongoDB: %w", err)
	}

	return nil
}
