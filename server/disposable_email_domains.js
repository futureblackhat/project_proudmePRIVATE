// Disposable / temp-mail domain blocklist used by /register to raise the
// cost of automated mass-account creation. NOT a complete defense, a
// motivated attacker can spin up a real domain or use Gmail aliases. The
// goal here is to block the cheap path: copy-paste a script that hits
// 10minutemail.com -> /register, where mailing back a 6-digit code costs
// the attacker nothing because they can read it instantly.
//
// Pairs with: register rate limit (5/hr/IP), age validation (rejects
// year=0 / year=9999 garbage), and the per-user daily token cap. Layered
// defense; this list is the cheapest of them.
//
// Maintenance: this list is intentionally small + obvious. Don't try to
// make it comprehensive (the moles outpace the whackers); keep it to
// well-known temp-mail brands so legitimate-but-rare domains don't get
// caught by mistake. If a real LSU pilot user complains they can't sign
// up because their school uses one of these, remove it.
//
// COPPA / kid-safety relevance: kids are a target audience for these
// services (parents enforcing email rules, kids using temp-mail to dodge
// account verification). Blocking them at signup is a small but real
// barrier against under-13 sign-ups bypassing parental email checks.

const DISPOSABLE_EMAIL_DOMAINS = new Set([
  // Mailinator family
  "mailinator.com", "mailinator.net", "mailinator.org",
  "mailinater.com", "mailinator2.com",
  // 10-minute / temp-mail brands
  "10minutemail.com", "10minutemail.net", "10minutemail.org",
  "tempmail.com", "temp-mail.org", "temp-mail.io", "tempmail.net",
  "tempmailo.com", "tempmailaddress.com",
  // Guerrilla Mail
  "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
  "guerrillamail.biz", "guerrillamail.de", "sharklasers.com",
  // Throwaway / yopmail / dispostable / others
  "throwawaymail.com", "throwaway.email",
  "yopmail.com", "yopmail.net", "yopmail.fr",
  "dispostable.com", "trashmail.com", "trashmail.net",
  "fakeinbox.com", "fakemail.net",
  "getnada.com", "nada.email",
  "mintemail.com", "mt2014.com", "spamgourmet.com",
  "maildrop.cc", "spam4.me", "moakt.com",
  "emailondeck.com", "emkei.cz",
  // Catch-all "mail+number" disposable services
  "mailcatch.com", "mailnesia.com", "anonbox.net",
  "mytemp.email", "mailpoof.com", "33mail.com",
]);

/**
 * Returns true if the given email's domain (case-insensitive) is in the
 * disposable blocklist. Returns false for any non-string input or any
 * email without a domain part, the upstream `validator.isEmail` already
 * rejects malformed addresses, so this should never see one in practice.
 */
function isDisposableEmail(rawEmail) {
  if (typeof rawEmail !== "string") return false;
  const at = rawEmail.lastIndexOf("@");
  if (at < 0 || at === rawEmail.length - 1) return false;
  const domain = rawEmail.slice(at + 1).trim().toLowerCase();
  if (!domain) return false;
  return DISPOSABLE_EMAIL_DOMAINS.has(domain);
}

module.exports = {
  isDisposableEmail,
  DISPOSABLE_EMAIL_DOMAINS,
};
