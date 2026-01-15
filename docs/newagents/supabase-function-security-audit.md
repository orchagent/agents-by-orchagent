# Supabase Function Security Audit & Fix

## The Original Post

### Exact Text

> ☠️ stop what you are doing and audit your database functions immediately
>
> today i gave myself $10,000 worth of free AI credits across 3 different "vibe coded" apps
>
> if you are not protecting yourself, bad actors will abuse this
>
> here is how i did and how to fix it 👇
>
> because many vibe coders (and the ai agents they use) don't realise that PostgreSQL database functions are PUBLIC executable by default
>
> if you create a function in supabase to handle internal logic, and you don't explicitly lock it down, anyone with your anon key (which is public!) can execute it.
>
> this is a massive blindspot in the "build fast" mentality.
>
> here is the fix to make sure bad actors can't bankrupt your startup overnight.
>
> go to your supabase SQL editor right now.
>
> for every sensitive function you have (especially ones dealing with credits, payments, or user permissions), execute this:
>
> ```sql
> -- Replace 'your_function_name' below
> REVOKE EXECUTE ON FUNCTION your_function_name FROM PUBLIC;
> REVOKE EXECUTE ON FUNCTION your_function_name FROM anon;
> REVOKE EXECUTE ON FUNCTION your_function_name FROM authenticated;
> -- Only allow service role to call it if needed for backend ops
> GRANT EXECUTE ON FUNCTION your_function_name TO service_role;
> ```
>
> i already dm'd the founders of the apps i tested so they could patch this.
>
> vibe coding is incredible for speed, but ai models assume a trusted environment. the internet is not a trusted environment.
>
> if you rely on defaults, you will get cooked. stay safe.

### Summary

The post warns about a critical security vulnerability in Supabase applications: PostgreSQL functions are publicly executable by default. The author demonstrated this by exploiting three apps to give themselves $10,000 in free AI credits. The fix is to explicitly revoke execution permissions from public roles (`PUBLIC`, `anon`, `authenticated`) and only grant access to `service_role`, which is used by your backend.

---

## What We Were Doing Wrong

### Simple Terms

Every database function we created was like an unlocked door. Anyone who knew the door existed could walk through it and do whatever that function does - including resetting spending limits, manipulating credits, or messing with user data.

Supabase gives you two keys:
- **Anon key** - Public, embedded in your frontend JavaScript. Anyone can see it.
- **Service role key** - Secret, only used by your backend server.

The problem: our functions could be called by anyone with just the anon key. A bad actor could open their browser console, find the anon key in network requests, and call our functions directly.

### Technical Terms

PostgreSQL functions default to `EXECUTE` permission granted to `PUBLIC`. In Supabase's role hierarchy:

```
PUBLIC (everyone)
  └── anon (unauthenticated API requests)
  └── authenticated (logged-in users via API)
  └── service_role (backend only, bypasses RLS)
```

Our migrations created functions like this:

```sql
CREATE OR REPLACE FUNCTION reset_daily_spend()
RETURNS VOID AS $$
BEGIN
    UPDATE agents SET current_daily_spend = 0, ...
END;
$$ LANGUAGE plpgsql;
-- No REVOKE statement = PUBLIC can execute
```

Supabase exposes all functions via the PostgREST API at:
```
POST https://<project>.supabase.co/rest/v1/rpc/<function_name>
```

An attacker could call:
```bash
curl -X POST 'https://crwvfclnioryheleslux.supabase.co/rest/v1/rpc/reset_daily_spend' \
  -H "apikey: <your-public-anon-key>" \
  -H "Content-Type: application/json"
```

This would reset ALL agent spending limits across the entire platform.

### Affected Functions (11 total)

| Function | What an attacker could do |
|----------|--------------------------|
| `reset_daily_spend()` | Reset all spending limits for all agents |
| `reserve_agent_downstream_spend()` | Manipulate credit reservations |
| `finalize_agent_downstream_spend()` | Mark fake spend as complete |
| `release_agent_downstream_spend()` | Release held credits |
| `check_and_increment_calls()` | Bypass rate limiting |
| `upsert_llm_key()` | Overwrite users' API keys |
| `fork_agent()` | Create unauthorized agent copies |
| `add_star()` | Inflate star counts |
| `remove_star()` | Deflate star counts |
| `get_user_providers()` | Enumerate user configurations |
| `user_can_call_agent()` | Probe agent access permissions |

---

## What We Fixed

### Simple Terms

We locked all the doors. Now only your backend server (using the secret service role key) can call these functions. Anyone trying to call them with the public anon key gets rejected.

### Technical Terms

Created migration `20260215000000_secure_function_permissions.sql` that:

1. **Revokes execution from all public roles:**
```sql
REVOKE EXECUTE ON FUNCTION reset_daily_spend FROM PUBLIC, anon, authenticated;
-- (repeated for all 11 functions)
```

2. **Grants execution only to service_role:**
```sql
GRANT EXECUTE ON FUNCTION reset_daily_spend TO service_role;
-- (repeated for all 11 functions)
```

### Before vs After

**Before:**
```
Function: reset_daily_spend()
├── PUBLIC: ✅ can execute
├── anon: ✅ can execute
├── authenticated: ✅ can execute
└── service_role: ✅ can execute
```

**After:**
```
Function: reset_daily_spend()
├── PUBLIC: ❌ denied
├── anon: ❌ denied
├── authenticated: ❌ denied
└── service_role: ✅ can execute
```

### API Response Change

**Before (attacker succeeds):**
```bash
curl -X POST '.../rpc/reset_daily_spend' -H "apikey: <anon-key>"
# Response: 200 OK (spending reset!)
```

**After (attacker blocked):**
```bash
curl -X POST '.../rpc/reset_daily_spend' -H "apikey: <anon-key>"
# Response: 403 Forbidden
# {"message":"permission denied for function reset_daily_spend"}
```

---

## Files Changed

```
supabase/migrations/20260215000000_secure_function_permissions.sql (created)
```
