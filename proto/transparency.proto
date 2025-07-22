//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

syntax = "proto3";
package transparency;

option go_package = "github.com/signalapp/keytransparency/tree/transparency/pb";

message PrefixProof {
    repeated bytes proof = 1;
    uint32 counter = 2;
}

// AuditorTreeHead contains an auditor's signature on its most recent view of the log.
message AuditorTreeHead {
  uint64 tree_size = 1;
  int64 timestamp = 2;
  bytes signature = 3;
}

// TreeHead contains the key transparency service operator's signature on the most recent version of the
// log.
message TreeHead {
    uint64 tree_size = 1;
    int64 timestamp = 2;
    // The key transparency service operator provides one Signature object per auditor.
    repeated Signature signatures = 3;
}

// The signature incorporates the auditor public key so the service provides one signature per auditor.
message Signature {
  bytes auditor_public_key = 1;
  bytes signature = 2;
}

// FullAuditorTreeHead is provided to end-users when third-party auditing is used,
// as evidence that the log is behaving honestly.
message FullAuditorTreeHead {
    AuditorTreeHead tree_head = 1;
    optional bytes root_value = 2;
    repeated bytes consistency = 3;
    bytes public_key = 4;
}

// FullTreeHead wraps a basic TreeHead with additional information that may be
// needed for validation.
message FullTreeHead {
    TreeHead tree_head = 1;
    repeated bytes last = 2;
    repeated bytes distinguished = 3;
    repeated FullAuditorTreeHead full_auditor_tree_heads = 4;
}

// ProofStep is the output of one step of a binary search through the log.
message ProofStep {
    PrefixProof prefix = 1;
    bytes commitment = 2;
}

// SearchProof contains the output of a binary search through the log.
message SearchProof {
    uint64 pos = 1;
    repeated ProofStep steps = 2;
    repeated bytes inclusion = 3;
}

// UpdateValue wraps the new value for a key.
message UpdateValue {
    bytes value = 1;
}

// Consistency specifies the parameters of the consistency proof(s) that should
// be returned.
message Consistency {
    optional uint64 last = 1;
    optional uint64 distinguished = 2;
}

// TreeSearchRequest is a KT-internal data structure used to look up a key.
message TreeSearchRequest {
    bytes search_key = 1;
    Consistency consistency = 2;
}

// TreeSearchResponse is the output of executing a search on the tree.
message TreeSearchResponse {
    FullTreeHead tree_head = 1;
    bytes vrf_proof = 2;
    SearchProof search = 3;

    bytes opening = 4;
    UpdateValue value = 5;
}

// UpdateRequest comes from a user that wishes to update a key.
message UpdateRequest {
    bytes search_key = 1;
    bytes value = 2;
    Consistency consistency = 3;
    // This field is only populated for updates that overwrite
    // an existing search key to point to a dummy value.
    // To avoid a race condition, KT compares what the search key currently maps to
    // against the expected value, and only proceeds with the update if they match.
    bytes expected_pre_update_value = 4;
    // A flag that clients can set if they want to get back an update response that they can
    // use to verify the update.
    bool return_update_response = 5;
}

// UpdateResponse is the output of executing an update on the tree.
message UpdateResponse {
    FullTreeHead tree_head = 1;
    bytes vrf_proof = 2;
    SearchProof search = 3;

    bytes opening = 4;
}

// MonitorKey is a single key that the user would like to monitor.
message MonitorKey {
    bytes search_key = 1;
    // The position of the last log entry verified by the client
    // to be in the direct path to the identifier
    uint64 entry_position = 2;
    // the commitment index for the search key
    bytes commitment_index = 3;
}

// MonitorRequest comes from a user that wishes to monitor a set of keys.
message MonitorRequest {
    repeated MonitorKey keys = 1;
    Consistency consistency = 2;
}

// MonitorProof proves that a single key has been correctly managed in the log.
message MonitorProof {
    repeated ProofStep steps = 1;
}

// MonitorResponse is the output of a monitoring operation.
message MonitorResponse {
    FullTreeHead tree_head = 1;
    repeated MonitorProof proofs = 2;
    repeated bytes inclusion = 4;
}

// AuditorProof provides additional information about a change to the tree to
// improve the efficiency of auditors.
message AuditorProof {
    message NewTree {}

    message DifferentKey {
        repeated bytes copath = 1;
        bytes old_seed = 2;
    }

    message SameKey {
        repeated bytes copath = 1;
        uint32 counter = 2;
        uint64 position = 3;
    }

    oneof proof {
        NewTree new_tree = 1;
        DifferentKey different_key = 3;
        SameKey same_key = 4;
    }
}

// AuditorUpdate is the structure shared with a third-party auditor for a single
// update to the tree.
message AuditorUpdate {
    bool real = 1;
    bytes index = 2;
    bytes seed = 3;
    bytes commitment = 4;
    AuditorProof proof = 5;
}