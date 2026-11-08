package mpcpartyv1

// CodeSigningStarted is ErrorDetail.code of a 2-of-3 Sign failure that happened AFTER signing messages may have been exchanged.
// A TRANSPORT or UNAVAILABLE failure without it happened before any signing message (connect, OPEN, ACK, a refusing or
// unreachable peer): the caller may try another coordinator. With it, it must not.
const CodeSigningStarted uint32 = 0xff0c0005
