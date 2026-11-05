// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

//! Library surface of the warden package. The binary (`main.rs`) carries the
//! in-VM PID 1; only the dependency-free wire parser is exposed here so the
//! fuzz target can call the exact code the warden runs without pulling in
//! tokio, the sandbox or the mount machinery.

pub mod auth;
pub mod config;
pub mod frame_parse;
pub mod pure;
