// Storybook for the default pages (ADR 0025): every form in every state, built into the GitHub Pages site at
// docs/storybook/. A devDependency only; nothing here is in the package.
import type { StorybookConfig } from "@storybook/html-vite"

const config: StorybookConfig = {
  framework: "@storybook/html-vite",
  stories: ["../stories/*.stories.ts"],
  core: { disableTelemetry: true },
}

export default config
