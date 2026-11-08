import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compileFromFile } from "json-schema-to-typescript";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.resolve(__dirname, "../../../packages/contracts/schemas");
const tsOutFile = path.resolve(__dirname, "../../../packages/contracts/ts/index.ts");

async function main() {
  const schemaFiles = [
    "Entity.json",
    "Technique.json",
    "WSMessage.json",
    "Event.json",
    "Signal.json",
    "Incident.json",
    "GuardDecision.json",
    "SourceHealth.json",
    "TelemetryStats.json",
    "AssetResponse.json",
    "BudgetStatusResponse.json",
    "SystemStatusResponse.json",
    "EvalSummaryResponse.json",
  ];

  let outputTs = "/* eslint-disable */\n/**\n * Auto-generated TypeScript data contracts for SentinelX.\n * DO NOT EDIT MANUALLY - Generated from Pydantic schemas via scripts/export_contracts.py\n */\n\n";

  const seenTypes = new Set();

  for (const file of schemaFiles) {
    const fullPath = path.join(schemasDir, file);
    if (!fs.existsSync(fullPath)) {
      console.warn(`Schema file not found: ${fullPath}`);
      continue;
    }

    const ts = await compileFromFile(fullPath, {
      bannerComment: "",
      unreachableDefinitions: true,
      additionalProperties: false,
    });

    // Extract type definitions and avoid duplicate declarations across files
    const blocks = ts.split(/(?=export (?:interface|type))/g);
    for (const block of blocks) {
      const match = block.match(/export (?:interface|type) (\w+)/);
      if (match) {
        const typeName = match[1];
        if (!seenTypes.has(typeName)) {
          seenTypes.add(typeName);
          outputTs += block.trim() + "\n\n";
        }
      }
    }
  }

  outputTs = outputTs.replace(
    /(export interface Incident\s*\{[\s\S]*?explanation:\s*)Explanation;/m,
    "$1string[];"
  );

  outputTs += 'export type SourceStatus = "live" | "idle" | "stale" | "error";\n\n';
  outputTs = outputTs.replace(
    /(export interface SourceHealth\s*\{[\s\S]*?status:\s*)Status;/m,
    "$1SourceStatus;"
  );

  fs.mkdirSync(path.dirname(tsOutFile), { recursive: true });
  fs.writeFileSync(tsOutFile, outputTs.trim() + "\n", "utf-8");
  console.log(`Generated TypeScript contracts: ${tsOutFile}`);
}

main().catch((err) => {
  console.error("Error generating contracts:", err);
  process.exit(1);
});

