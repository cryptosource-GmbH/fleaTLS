#!/bin/bash
rm -rf generated/html/*
rm -rf generated/latex/*
doxygen doxygen.cfg
