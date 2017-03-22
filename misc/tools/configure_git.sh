#!/bin/bash
git config --global push.default matching
git config --global push.followTags true
git config --global remote.origin.tagopt --tags
