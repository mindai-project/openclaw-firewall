#!/usr/bin/env node
import { Command } from "commander";
import { registerFirewallCli } from "./cli.js";

const program = new Command();
program.name("mindai-firewall");
registerFirewallCli(program, { logger: console });
program.parse(process.argv);
