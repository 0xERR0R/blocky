// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

import './styles/tokens.css'
import './styles/reset.css'
import { mount } from 'svelte'
import App from './App.svelte'

mount(App, { target: document.getElementById('app') })
