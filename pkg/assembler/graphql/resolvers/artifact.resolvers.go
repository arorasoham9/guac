package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.55

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestArtifact is the resolver for the ingestArtifact field.
func (r *mutationResolver) IngestArtifact(ctx context.Context, artifact *model.IDorArtifactInput) (string, error) {
	return r.Backend.IngestArtifact(ctx, artifact)
}

// IngestArtifacts is the resolver for the ingestArtifacts field.
func (r *mutationResolver) IngestArtifacts(ctx context.Context, artifacts []*model.IDorArtifactInput) ([]string, error) {
	return r.Backend.IngestArtifacts(ctx, artifacts)
}

// Artifacts is the resolver for the artifacts field.
func (r *queryResolver) Artifacts(ctx context.Context, artifactSpec model.ArtifactSpec) ([]*model.Artifact, error) {
	return r.Backend.Artifacts(ctx, &artifactSpec)
}

// ArtifactsList is the resolver for the artifactsList field.
func (r *queryResolver) ArtifactsList(ctx context.Context, artifactSpec model.ArtifactSpec, after *string, first *int) (*model.ArtifactConnection, error) {
	return r.Backend.ArtifactsList(ctx, artifactSpec, after, first)
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
