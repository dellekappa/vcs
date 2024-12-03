/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dellekappa/vc-go/presexch"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	txCollection = "oidc4vp_tx"
)

type txDocument struct {
	ID                     primitive.ObjectID     `bson:"_id,omitempty"`
	ProfileID              string                 `bson:"profileIDID"`
	ProfileVersion         string                 `bson:"profileVersion"`
	PresentationDefinition map[string]interface{} `bson:"presentationDefinition"`
	ReceivedClaimsID       string                 `bson:"receivedClaimsID"`
	CustomScopes           []string               `bson:"customScopes,omitempty"`
	ExpireAt               time.Time              `bson:"expire_at"`
	TTL                    int32                  `bson:"ttl"`
}

type txUpdateDocument struct {
	ReceivedClaimsID string `bson:"receivedClaimsID"`
}

// TxStore manages profile in mongodb.
type TxStore struct {
	defaultTTL     time.Duration
	mongoClient    *mongodb.Client
	documentLoader jsonld.DocumentLoader
}

// NewTxStore creates TxStore.
func NewTxStore(
	ctx context.Context,
	mongoClient *mongodb.Client,
	documentLoader jsonld.DocumentLoader,
	vpTransactionDataTTLSec int32) (*TxStore, error) {
	s := &TxStore{
		defaultTTL:     time.Duration(vpTransactionDataTTLSec) * time.Second,
		mongoClient:    mongoClient,
		documentLoader: documentLoader,
	}

	if err := s.migrate(ctx); err != nil {
		return nil, fmt.Errorf("tx store migrate: %w", err)
	}

	return s, nil
}

func (p *TxStore) migrate(ctx context.Context) error {
	_, err := p.mongoClient.Database().Collection(txCollection).Indexes().CreateOne(ctx,
		p.mongoClient.NewExpirationIndex("expire_at"))
	if err != nil {
		return fmt.Errorf("create index for collection %s: %w", txCollection, err)
	}

	return nil
}

// Create creates transaction document in a database.
func (p *TxStore) Create(
	pd *presexch.PresentationDefinition,
	profileID, profileVersion string,
	profileTransactionDataTTL int32,
	customScopes []string,
) (oidc4vp.TxID, *oidc4vp.Transaction, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(txCollection)

	pdContent, err := mongodb.StructureToMap(pd)
	if err != nil {
		return "", nil, fmt.Errorf("create tx doc: %w", err)
	}

	ttl := p.defaultTTL
	if profileTransactionDataTTL > 0 {
		ttl = time.Duration(profileTransactionDataTTL) * time.Second
	}

	txDoc := &txDocument{
		ExpireAt:               time.Now().Add(ttl),
		TTL:                    int32(ttl.Seconds()),
		ProfileID:              profileID,
		ProfileVersion:         profileVersion,
		PresentationDefinition: pdContent,
		CustomScopes:           customScopes,
	}

	result, err := collection.InsertOne(ctxWithTimeout, txDoc)
	if err != nil {
		return "", nil, err
	}

	txID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	txDoc.ID = txID

	tx, err := txFromDocument(txDoc)
	if err != nil {
		return "", nil, err
	}

	return oidc4vp.TxID(txID.Hex()), tx, nil
}

// Get oidc4vp.Transaction by given strID.
func (p *TxStore) Get(strID oidc4vp.TxID) (*oidc4vp.Transaction, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(txCollection)

	id, err := txIDFromString(strID)
	if err != nil {
		return nil, err
	}

	txDoc := &txDocument{}

	err = collection.FindOne(ctxWithTimeout, bson.M{"_id": id}).Decode(txDoc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, oidc4vp.ErrDataNotFound
		}

		return nil, fmt.Errorf("tx find failed: %w", err)
	}

	if txDoc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, oidc4vp.ErrDataNotFound
	}

	return txFromDocument(txDoc)
}

// Delete deletes oidc4vp.Transaction from store.
func (p *TxStore) Delete(strID oidc4vp.TxID) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(txCollection)

	id, err := txIDFromString(strID)
	if err != nil {
		return err
	}

	_, err = collection.DeleteOne(ctxWithTimeout, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("delete tx: %w", err)
	}

	return nil
}

func (p *TxStore) Update(update oidc4vp.TransactionUpdate, _ int32) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(txCollection)

	id, err := txIDFromString(update.ID)
	if err != nil {
		return err
	}

	//nolint: govet
	result, err := collection.UpdateOne(ctxWithTimeout,
		bson.D{{"_id", id}}, bson.D{{"$set", txUpdateDocument{
			ReceivedClaimsID: update.ReceivedClaimsID,
		}}})
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("profile with given id not found")
	}

	return nil
}

func txIDFromString(strID oidc4vp.TxID) (primitive.ObjectID, error) {
	if strID == "" {
		return primitive.NilObjectID, nil
	}

	id, err := primitive.ObjectIDFromHex(string(strID))
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("tx invalid id(%s): %w", strID, err)
	}

	return id, nil
}

func txFromDocument(txDoc *txDocument) (*oidc4vp.Transaction, error) {
	pd := &presexch.PresentationDefinition{}

	err := mongodb.MapToStructure(txDoc.PresentationDefinition, pd)
	if err != nil {
		return nil, fmt.Errorf("oidc4vp tx manager: pd deserialization failed: %w", err)
	}

	return &oidc4vp.Transaction{
		ID:                     oidc4vp.TxID(txDoc.ID.Hex()),
		ProfileID:              txDoc.ProfileID,
		ProfileVersion:         txDoc.ProfileVersion,
		PresentationDefinition: pd,
		ReceivedClaimsID:       txDoc.ReceivedClaimsID,
		CustomScopes:           txDoc.CustomScopes,
	}, nil
}
