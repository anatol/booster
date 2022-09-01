#!/usr/bin/env bash

mkdir -p assets/tang
tangctl create > assets/tang/key.priv
tangctl public assets/tang/key.priv > assets/tang/key.pub
tangctl unpack-key --output-dir assets/tang assets/tang/key.priv
