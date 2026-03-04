/**
 * Special / test accounts that bypass normal billing and get elevated plans automatically.
 *
 * These accounts:
 *  - Are auto-upgraded to their designated plan on every login/register
 *  - Always bypass Stripe checkout → instant demo upgrade (never charged)
 *  - Return manualPlan:true from the billing portal (no Stripe portal)
 *  - Retain full access to test Stripe flows manually via the Stripe dashboard
 *
 * To add an account: add the email (lowercase) and the plan it should receive.
 */
const SPECIAL_ACCOUNTS = {
  'mkanaventi@gmail.com': 'team',
  'gbutler1738@gmail.com': 'team',
};

/**
 * Returns true if the email belongs to a special/test account.
 * @param {string} email
 */
function isSpecialAccount(email) {
  return !!(email && SPECIAL_ACCOUNTS[email.toLowerCase()]);
}

/**
 * Returns the plan for a special account, or null if not a special account.
 * @param {string} email
 * @returns {string|null}
 */
function getSpecialPlan(email) {
  return (email && SPECIAL_ACCOUNTS[email.toLowerCase()]) || null;
}

module.exports = { SPECIAL_ACCOUNTS, isSpecialAccount, getSpecialPlan };
