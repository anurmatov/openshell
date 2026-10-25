// SPDX-License-Identifier: Apache-2.0

import { copyFileSync } from 'node:fs';

// Keep the exact generated binary in the published dist closure; never decode,
// normalize or substitute language-runtime descriptor metadata during packaging.
copyFileSync(
  new URL('../src/create_descriptor.bin', import.meta.url),
  new URL('../dist/create_descriptor.bin', import.meta.url),
);
