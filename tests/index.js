const wallet = require('../main.js');

const isAltCoin = (coin => coin !== 'bitcoin');

function generate(passphrase, salt, power, coin, altCoin) {
	console.log("Generating " + coin)
	return new Promise(resolve => {
		wallet.generateWallet(passphrase, salt, power, coin,(result, wallet) => {
			if (wallet) {
				resolve(wallet)
			}
		}, altCoin);
	})
}

(async () => {
	const coins = ['bitcoin', 'litecoin', 'monero', 'ethereum', 'segwit', 'loki']
	const power = 'default';

	for(let coin of coins) {
		try {
			const result = await generate('pass', 'salt', power, coin, isAltCoin(coin));
			console.log(result)
		} catch (e) {
			console.log(e)
		}
	}
})();
