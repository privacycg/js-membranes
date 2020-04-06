# JS Isolation via Origin Labels and Membranes

A [Proposal](https://privacycg.github.io/charter.html#proposals)
of the [Privacy Community Group](https://privacycg.github.io/).

## Authors:

* Pete Snyder <pes@brave.com>
* Brendan Eich <brendan@brave.com>
* Pranjal Jumde <pranjal@brave.com>

## Participate
- https://github.com/privacycg/js-membranes/issues

## Table of Contents [if the explainer is longer than one printed page]

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Introduction](#introduction)
- [Problem](#problem)
- [Goals](#goals)
- [Out of Scope](#out-of-scope)
- [Proposal](#proposal)
  - [Example Mediated Cases](#example-mediated-cases)
  - [Unmediated Cases](#unmediated-cases)
- [FAQ](#faq)
  - [How is this different from COWL? https://www.w3.org/TR/COWL/](#how-is-this-different-from-cowl-httpswwww3orgtrcowl)
  - [How is this different from Feature-Policy? https://wicg.github.io/feature-policy/](#how-is-this-different-from-feature-policy-httpswicggithubiofeature-policy)
  - [How do you avoid `adoption fatigue` with this proposal?](#how-do-you-avoid-adoption-fatigue-with-this-proposal)
  - [What is the performance impact of this proxy-approach?](#what-is-the-performance-impact-of-this-proxy-approach)
  - [Why would this get more uptake than CSP and other deployed protections?](#why-would-this-get-more-uptake-than-csp-and-other-deployed-protections)
- [Stakeholder Feedback / Opposition](#stakeholder-feedback--opposition)
- [References & acknowledgements](#references--acknowledgements)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction
This document describes a mechanism that allows user agents, extensions and sites to constrain less-or-untrusted script access to Web APIs and document state, without requiring existing code to be rewritten.

The proposal is designed to solve a problem without a current solution (how to constrain scripts from the document, without rewriting a web application), not to solve similar-but-distinct problems that already have solutions (protecting script state from other scripts).

## Problem
HTML and JavaScript currently lack a method for including remote code without giving that code access to all of the capabilities of the including origin, including `document`, `navigator` and other related Web API and DOM defined interfaces. An author may wish to include code to perform form validation, but not wish to give it access to other parts of the document, cookies, or other document capabilities.

The source of this problem is that script included from any origin is treated by the runtime identically.

This proposal aims to solve this problem through an opt-in method by which an elevated party (browser agent, browser extension, or hosting origin) can, at runtime, control what resources are accessible by third party code (and less trusted 1p code). The proposal uses the concept of membranes, implemented via an ES6-proxy-based interface, enforced by elevated / trusted first-party code.

The proposal aims to be compatible with existing code, and to allow users to apply it to only subsets of existing code as needed, without any changes to the existing, untrusted code.  All new mediation logic exists within new, distinct code units.  It is a primary goal of this proposal that these protections be able to be applied to existing code, w/o requiring any code rewriting (i.e. the protection / mediation code must be able to work without rewriting first or third party code).

The first party can “opt in” contexts that should be restricted to mediated DOM, Web API, and document access.  We refer to this process as assigning origin labels.  By construction, whenever labeled code is given access to a protected object, it is given only a new, “membrane” proxy object; untrusted code cannot gain direct access to objects on the other side of the security boundary.

## Goals

### In Scope
* Controlling third party script access to cookies, form fields, fingerprinting vectors, etc.
* Restricting a third party form validation library to a certain form in the document, but not to other page resources.
* Preventing untrusted code from carrying out timing attacks by calling high resolution timers multiple times.
* Prevent data exfiltration using code injections.
* Protecting builtins / prototypes: these are similarly global shared state, but not targeted by this proposal (though a similar approach might be useful)

### Out of Scope
* Protecting script local code and state: there are already methods for doing so (modules, closures, etc.)
* Applying protections to "downstream" scripts. While this proposal aims to be compatible with, and to be improved by, JavaScript engines that accurately trace JavaScript code unit lineage (e.g. script X was injected by script Y, which was included in the original document text), it intentionally does not require it, since not all JavaScript engines currently track such information comfortably.  But if / when all engines do, we imagine extending that information to the membrane policy layer as well.

### In Scope, Tricky Cases
* Because protections must be able to be applied to all existing, this includes code that follows non-best-practice design patterns.  For example, popular libraries like MooTools intentionally modify builtin prototypes; this proposal must allow for such code to continue working, but controlling which scripts get access to which prototype chains.

## Proposal
This proposal is to allow first parties to limit access to the functionality and global data (in the document or otherwise) that less trusted parties can access.  The first party indicates which following origins of code should be constrained.  This could be any combination of third party code and less-trusted first party code on the page.

The first party labels code as “trusted” (e.g. able to intermediate on other access to global functionality and state) through syntax similar to CSP (e.g. with a nonce or hash).  The first party can label at most one script as trusted per top level URL.

**Trusted code** is JavaScript code that executes as normal, except that it has access to a global function called “registerTrustProxy”.  Trusted code can call this function to register different membranes to different, less trusted code.  This code is guaranteed to always run with access to its own prototypes, in its own realm-like world.  The membrane API is similar to that of ES6 proxies, with modifications to allow the handler object to distinguish which origin is attempting to access document state and web capabilities.  Trusted code must execute before any other code units on the page executes, otherwise page execution is halted.  We also intend browsers and browser extensions to be able to perform this mediation, through the addition of a new privilege in the WebExtension standard.

**Untrusted code** is any code from an origin (first or third party) labeled as untrusted / mediated by the first party code.

For example, the following code shows trusted code registering two membranes, one that mediates property accesses on all first party code, and code from an untrusted third party.  The second membrane prevents any code on the page from accessing a high resolution timer.

```javascript
const passwordLibOrigin = "<password validating origin>";
const cookieLibOrigin = "<origin that serves a trusted cookie library, likely 1p>";

// Indicate that we want to interpose on all first party scripts (including inlined),
// and scripts from two script-include origins.
const interposedOrigins = ["<first party>", passwordLibOrigin, cookieLibOrigin];

// This is a straw proposal, meant to show that different types of information
// could be provided to the proxy to enable different types of policies.
interface ScriptInfo {
  source: string,       // Text of the script being executed.
  context: string,      // One of “inline”, “fetched”, “JSURL”, “HTMLAttribute”, etc.
  element: HTMLElement, // The HTML element in the document responsible for the script running.
  url?: URL             // Empty if inline script, JSURL, HTML attribute context.
}


window.registerMembraneProxy(interposedOrigins, {
   get: (target, prop, scriptInfo: ScriptInfo) => {
       // Prevent any third party scripts from accessing cookies, only the
       // exception of a known script element.
       if (target === window.document && prop === "cookie") {
           if (scriptOrigin === cookieLibOrigin) {
               return Reflect.get(target, prop);
           }
           return "fake cookie value";
       }

       // Restrict the password library from accessing any DOM functionality other
       // than the value of password fields.
       if (scriptInfo.url.origin === passwordLibOrigin) {
           if (Object.getPrototypeOf(target) === window.HTMLInputElement &&
               	target.type === "password" &&
               	prop === "value") {
               return Reflect.get(target, prop);
           }
           return "bad bad bad";
       }

       // Otherwise, find or create the membrane wrapping the result of this get.
       return Reflect.get(target, prop);
   },
});

// Prevent any code units from calling a source of high resolution timestamps.
// Allow all other kinds of calls.
window.registerMembraneProxy(["*"], {
   apply: (target, thisArg, argumentsList, scriptOrigin) => {
       if (target === window.performance.now) {
           return Date.now();
       }
	return Reflect.apply(target, thisArg, argumentsList);
   },
});
```

The `window.registerMembraneProxy` takes the following arguments:
* An array, containing any number of the following
  * `<first party>`: Indicating that other code on the first party should be treated as untrusted.
  * A domain match pattern, with the scheme portion optional: Indicating script units with URLs that match the match pattern (when the URL is normalized to an absolute URLs) should be treated as untrusted.
  * `*`: Indicating all script units should be treated as untrusted.
* An object, matching the shape of a ES6 Proxy handler, with each function taking an additional optional scriptOrigin parameter.

Trusted membranes register functions that are invoked whenever labeled code attempts to cross a label boundary.  Examples of such label boundary crossings include untrusted code accessing a built-in object, accessing properties or methods on DOM nodes, or accessing global objects outside of its membrane.

Trusted code can then choose to respond to each request attempt by returning a new, mediated object that corresponds to the requested resource. The trusted code can also choose to respond with any other value, including bottom values; or by throwing an exception.

Trusted code cannot return references to globally accessible objects and functions to untrusted code.  Instead, trusted code can only choose to give access to new proxy objects that correspond to the requested functionality.  Any value retrieved by untrusted code is automatically membrane-wrapped, with the exception of core JS values (string, number, boolean, undefined, null).

### Example Mediated Cases
* Labeled (opt-ed in via a registerMembraneProxy call) 3p code that attempts to access Web API methods.
* Labeled 3p code that attempts to access document structure (DOM).
* 1p code that is not labeled as trusted, attempting to do any of the above, when the 1p labels itself as untrusted.  (e.g. XSS code injection)

### Unmediated Cases
* 3p, labeled code that accesses only local (to the 3p) defined data and functions.
* 3p code that is not labeled for mediation by the 1st party.
* 1p, trusted code that accesses any data structure.

## FAQ
### How is this different from COWL? https://www.w3.org/TR/COWL/
COWL enables web-authors to label sensitive data before providing it to third parties. But, it does not restrict DOM, WebAPI access for third-parties.

### How is this different from Feature-Policy? https://wicg.github.io/feature-policy/
Feature-Policy only allows a fixed set of features to be blocked, in embedded documents, and with a boolean label.

### How do you avoid `adoption fatigue` with this proposal?
This proposal does not require any code-rewrite. It’s opt-in and allows web-authors to restrict 3p scripts incrementally. Web-Authors need not restrict all 3p scripts at once.

### What is the performance impact of this proxy-approach?
This is unknown currently, but expected to be minimal when needed, given the high performance of ES6 Proxies in current JS runtimes.

Agoric's SES is an attempt to solve all of the use cases below using object capabilities. How is this better? https://github.com/Agoric/SES
SES requires authors to rewrite code.  Additionally, while related proposals like the TC39 SES proposal are intended to isolate scripts from manipulating shared globals by (i) providing unmodified versions of built ins (Array.prototype, String.prototype, etc) to each execution context, and (ii) preventing scripts from "reaching out" of their execution context and modifying the environment of other scripts, this is nearly the opposite of this proposal. This proposal aims to allow multiple scripts to interact with shared objects (`document`, `navigator`, etc.), but with trusted script being able to impose access controls on less-trusted script.

What about code that attempts to evade policy labels by injecting inline code, etc.
The proposal would require labeling code units with something akin to back-pointers to where each code unit came from.

### Why would this get more uptake than CSP and other deployed protections?
User agents and extensions can define their own policies w/o requiring server opt-in; the proposal would allow for new protections w/o a single site using the system. Sites using the system would just extend the protections delivered by the system.
Related, we anticipate that policies could be shared between users, similar to Easylist or other crowd-sourced privacy protecting tools.  This would further extend the privacy protections provided to users.
Anecdotally we expect that requiring the use of a header would risk seeing low adoption; the proposal is designed to allow users to see benefits immediately (i.e. client-side policies) until adoption ticks up.

<sup>1</sup> We have several ideas for how this might work (e.g. HTTP header pointing to a script at a .well_know location, etc.) but the core of this proposal is the enforcement mechanism / policy definitions; how to inform the browser of a policy for a page is a simpler issue.
