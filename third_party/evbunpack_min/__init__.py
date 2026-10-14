"""Minimal, bounded EVB tree reader adapted from evbunpack 0.2.6.

Upstream: mos9527/evbunpack, commit
ee7b647acf2a46617b0c448dfa83d63132ea917b (Apache-2.0).
This adaptation removes PE restoration, decompression, command-line entry
points and writes. It reads only the uncompressed modern external-file tree.
See parser.py and licenses/evbunpack-Apache-2.0.txt.
"""

from .parser import EVB_MAGIC, NODE_TYPE_FILE, NODE_TYPE_FOLDER, external_tree

__all__ = ["EVB_MAGIC", "NODE_TYPE_FILE", "NODE_TYPE_FOLDER", "external_tree"]
