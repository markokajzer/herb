import { PrismVisitor, PrismNodes } from "@herb-tools/core"
import { ParserRule } from "../types.js"
import { BaseRuleVisitor } from "./rule-utils.js"
import { getTagLocalName, getAttribute, getStaticAttributeValue, hasAttributeValue } from "@herb-tools/core"

import type { UnboundLintOffense, LintContext, FullRuleConfig } from "../types.js"
import type { ParseResult, ParserOptions, ERBContentNode, ERBBlockNode, HTMLOpenTagNode } from "@herb-tools/core"

const JAVASCRIPT_HELPERS = new Set([
  "javascript_tag",
  "javascript_include_tag",
  "javascript_pack_tag",
])

interface JavaScriptHelperCall {
  name: string
  nonce: "unknown" | "missing" | "present";
}

class JavaScriptTagHelperCallCollector extends PrismVisitor {
  public readonly javascriptTags: JavaScriptHelperCall[] = []
  private currentCall: JavaScriptHelperCall | null = null

  visitCallNode(node: PrismNodes.CallNode): void {
    const isJavaScriptHelper = JAVASCRIPT_HELPERS.has(node.name) || this.isTagScriptCall(node)

    if (isJavaScriptHelper) {
      this.currentCall = { name: node.name, nonce: "unknown" }
      this.javascriptTags.push(this.currentCall)
    }

    super.visitCallNode(node)

    if (isJavaScriptHelper && this.currentCall) {
      if (this.currentCall.nonce === "unknown") {
        this.currentCall.nonce = "missing"
      }

      this.currentCall = null
    }
  }

  visitAssocNode(node: PrismNodes.AssocNode): void {
    if (this.currentCall &&
        node.key.constructor.name === "SymbolNode" &&
        (node.key as PrismNodes.SymbolNode).unescaped.value === "nonce") {
      this.currentCall.nonce = "present"
    }

    super.visitAssocNode(node)
  }

  private isTagScriptCall(node: PrismNodes.CallNode): boolean {
    return node.name === "script" &&
      node.receiver !== null &&
      node.receiver.constructor.name === "CallNode" &&
      (node.receiver as PrismNodes.CallNode).name === "tag"
  }
}

class RequireScriptNonceVisitor extends BaseRuleVisitor {
  visitHTMLOpenTagNode(node: HTMLOpenTagNode): void {
    if (getTagLocalName(node) === "script") {
      this.checkScriptNonce(node)
    }
  }

  visitERBContentNode(node: ERBContentNode): void {
    this.checkPrismNode(node)
  }

  visitERBBlockNode(node: ERBBlockNode): void {
    this.checkPrismNode(node)

    super.visitERBBlockNode(node)
  }

  private checkScriptNonce(node: HTMLOpenTagNode): void {
    if (!this.isJavaScriptTag(node)) return

    const nonceAttribute = getAttribute(node, "nonce")

    if (!nonceAttribute || !hasAttributeValue(nonceAttribute)) {
      this.addOffense(
        "Missing a `nonce` attribute on `<script>` tag. Use `request.content_security_policy_nonce`.",
        node.tag_name!.location,
      )
    }
  }

  private isJavaScriptTag(node: HTMLOpenTagNode): boolean {
    const typeAttribute = getAttribute(node, "type")
    if (!typeAttribute) return true

    const typeValue = getStaticAttributeValue(typeAttribute)
    if (typeValue === null) return true

    return typeValue === "text/javascript" || typeValue === "application/javascript"
  }

  private checkPrismNode(node: ERBContentNode | ERBBlockNode): void {
    const prismNode = node.prismNode
    if (!prismNode) return

    const collector = new JavaScriptTagHelperCallCollector()
    collector.visit(prismNode)

    collector.javascriptTags
      .filter(call => call.nonce === "missing")
      .forEach(() => {
        this.addOffense(
          "Missing a `nonce` attribute. Use `nonce: true`.",
          node.location,
        )
      })
    }
  }

export class ERBRequireScriptNonceRule extends ParserRule {
  static ruleName = "erb-require-script-nonce"

  get defaultConfig(): FullRuleConfig {
    return {
      enabled: true,
      severity: "warning"
    }
  }

  get parserOptions(): Partial<ParserOptions> {
    return {
      prism_nodes: true,
    }
  }

  check(result: ParseResult, context?: Partial<LintContext>): UnboundLintOffense[] {
    const visitor = new RequireScriptNonceVisitor(this.ruleName, context)

    visitor.visit(result.value)

    return visitor.offenses
  }
}
