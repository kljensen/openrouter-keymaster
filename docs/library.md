# Using the core crate

A Rust program can call the same operations the binary does. Depend on the
library and skip the CLI:

```toml
[dependencies]
openrouter-keymaster-core = { git = "https://github.com/kljensen/openrouter-keymaster" }
serde_json = "1"
zeroize = "1"
```

[`compatibility.md`](compatibility.md#the-core-crates-rust-api) is what the
crate promises and what it does not. [`ADR-0003`](adr/0003-core-library-split.md)
is why the split exists.

## The context

Every operation is a function in `ops` taking an owned `Context` — the two file
paths, the endpoint options, the credential, an optional workspace scope, and an
optional delivery callback — and returning the command's report rather than
printing it:

```rust
use openrouter_keymaster_core::ops::{self, Context, ManagementKey, Options, Paths};
use zeroize::Zeroizing;

fn print_plan(secret: String) -> Result<(), Box<dyn std::error::Error>> {
    let context = Context {
        paths: Paths { config: "keymaster.toml".into(), state: "state.json".into() },
        options: Options::default(),
        key: Some(ManagementKey::from_secret(Zeroizing::new(secret))?),
        workspace: None,
        deliver: None,
    };

    let outcome = ops::plan(context)?;
    println!("{}", serde_json::to_string_pretty(&outcome.report)?);
    Ok(())
}
```

`Outcome { report, error }` keeps the report beside a partial failure; `Err` is
for the runs with no report to give. A plan's `fingerprint` can be handed back
to `ops::apply`, which recomputes the plan under the lock and writes only if
every input that decides the outcome is still what it was.

**Two rules the crate cannot enforce for you.** The HTTP client is blocking and
panics on a thread that is running a Tokio runtime, so an async host moves the
whole call — context in, outcome out — to `tokio::task::spawn_blocking` or an
equivalent; that is what `Context: Send + 'static` is for. And the state lock
refuses a concurrent writer rather than queueing it, so a process that serves
many requests serializes its own operations on one state file.

## Receiving a key's plaintext in your own code

A `caller` receiver hands a new key's plaintext to the host instead of writing
it to a file or piping it to a program. The configuration names the destination,
and `Context.deliver` carries the code:

```toml
[receivers.host]
type = "caller"
destination = "vault/jobfeed"
```

```rust
use openrouter_keymaster_core::ops::DeliveryOutcome;

let context = Context {
    deliver: Some(Box::new(|metadata, plaintext| {
        // `metadata` carries the address, hash, generation, operation ID, and
        // the configured destination — all non-secret. `expose()` is the one
        // way to read the key, and this call is the only place it appears.
        match store(metadata.destination().unwrap_or_default(), plaintext.expose()) {
            Ok(()) => DeliveryOutcome::delivered("stored in the vault"),
            Err(error) if error.wrote_nothing() => DeliveryOutcome::rejected(error.to_string()),
            Err(error) => DeliveryOutcome::ambiguous(error.to_string()),
        }
    })),
    ..context
};

let outcome = ops::apply(context, None)?;
```

One operation may issue several keys, so the callback is called once per
delivered key and routes on the metadata, never on call order. A panic inside it
is caught and recorded as ambiguous. Keymaster's guarantees about the plaintext
end at this call.

`plan` and `status` never need a callback: the destination is configuration. An
operation that would *issue* a key through a `caller` receiver with no callback
refuses before any remote write or issuance — `apply` checks the whole plan
ahead of its first phase, so not even a guardrail earlier in the same run is
created. The one local write that can precede the refusal is the promotion of an
already-delivered key, which the report shows. That refusal is what the CLI
always gets, since it has no host code to deliver into.
[`receiver-protocol.md`](receiver-protocol.md#the-caller-receiver) is the full
contract.

## Scoping a run to one workspace

`Context.workspace`, and the `--workspace UUID` global option that sets it, name
the one OpenRouter workspace a run places resources in and reports on. With a
scope, a configuration that names a different workspace is refused before any
request — a key or guardrail whose `workspace_id` or `workspace` block resolves
elsewhere, and a `[workspaces.NAME]` block that is not already bound to the
scope, since a scoped run cannot create a workspace whose new UUID could never
be the one it was scoped to. Every key, guardrail, and log destination the run
creates is placed in the scope; `plan` and `status` leave out `unmanaged`
resources from other workspaces; and matching by *name* — adoption candidates,
and the collision check before a guarded recreation — considers only resources
in the scope, so another club's identically named key cannot block this one. The
plan fingerprint covers the scope, so a scoped plan can never be applied
unscoped.

**It is not an isolation mechanism.** The snapshot is still the whole
organization, because state records no workspace per binding: filtering the
snapshot would make every out-of-scope binding look missing. So a bound resource
is judged present or missing exactly as it is without a scope, and two scopes
pointed at one state file produce correct but mixed plans. A host that wants
clubs to stay separate keeps one configuration and one state file per club.

## One context per tenant, from an async handler

The pieces above compose into what a web application does: a request arrives for
one club, the handler builds a context scoped to that club's workspace with a
callback that stores the plaintext where the club can see it, and moves the
whole call off the async runtime.

```rust
async fn issue_key(club: Club) -> Result<ApplyReport, Error> {
    let context = Context {
        paths: Paths { config: club.config.clone(), state: club.state.clone() },
        options: Options::default(),
        key: Some(ManagementKey::from_secret(vault.management_key()?)?),
        // This club's workspace. Every key and guardrail the run creates is
        // placed here, and a configuration naming another workspace is refused
        // before any request goes out.
        workspace: Some(club.workspace.clone()),
        deliver: Some(Box::new(move |metadata, plaintext| {
            match vault.store(metadata.destination().unwrap_or_default(), plaintext.expose()) {
                Ok(()) => DeliveryOutcome::delivered("stored for the club"),
                Err(error) if error.wrote_nothing() => DeliveryOutcome::rejected(error.to_string()),
                Err(error) => DeliveryOutcome::ambiguous(error.to_string()),
            }
        })),
    };

    // The client is blocking and panics on a runtime thread, and the state lock
    // refuses a concurrent writer rather than queueing it — so the whole call
    // moves to a blocking thread, and the application serializes the calls that
    // share one club's state file.
    let outcome = tokio::task::spawn_blocking(move || ops::apply(context, None)).await??;
    Ok(outcome.report)
}
```

**One configuration and one state file per club**, as the paths above say. The
scope guards placement and filters reports; it does not isolate.

**How much a club may spend is the application's policy, not Keymaster's.**
Keymaster writes the caps OpenRouter enforces — a workspace budget where the
account's plan has them, a guardrail limit, a per-key `limit_usd` — and reports
what `spend` says was used. It does not decide what a club is allowed, does not
sum spend across clubs, and does not stop issuing when some total is reached.
Deciding that a club gets ten dollars a month, sizing the key it asks for, and
refusing the eleventh request belong to the application, which is the only place
that knows what a club is.
