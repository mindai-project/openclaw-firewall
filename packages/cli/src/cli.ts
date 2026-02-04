#!/usr/bin/env node
import { Command } from "commander";
import { registerFirewallCli } from "@mindai/openclaw-tool-firewall";

// Standalone CLI entrypoint for the firewall.
const program = new Command();
program.name("mindai-firewall");
registerFirewallCli(program, { logger: console });
program.parse(process.argv);
