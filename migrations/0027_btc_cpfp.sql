-- Bitcoin CPFP: a child transaction that spends the change of a stuck send back to the same shard and pays for both. It is an attempt of the same owner
-- as the send it pulls in, kind 'cpfp'. It never replaces a send (it spends the send's output), so "latest send" and "highest fee" readers that ask for
-- kind 'send' do not see it.
ALTER TABLE btc_attempts DROP CONSTRAINT IF EXISTS btc_attempts_kind_check;
ALTER TABLE btc_attempts ADD CONSTRAINT btc_attempts_kind_check CHECK (kind IN ('send', 'cancel', 'cpfp'));
