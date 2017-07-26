

const verify = async (service, email, password) => {

	// Getting member system agent
	let agent = service.getContext().get('Member')[service.memberAgent];

	// Getting database agent
	let dbAgent = service.getContext().get('MySQL')[agent.dbAgentName];

	// Finding member by using email
	let qstr = [
		'SELECT `id`, `name`, `email`, `salt`, `password`',
		'FROM `Member`',
		'WHERE',
		'`email` = ?'
	].join(' ');
	let [ records ] = await dbAgent.query(qstr, [ email ]);
	if (records[0].length === 0) {
		let e = new Error('No such member');
		e.name = 'NotExist';
		throw e;
	}

	// Check password
	if (agent.encryptPassword(records[0].salt, password) !== records[0].password) {
		ctx.throw(401);
		let e = new Error('Password is incorrect');
		e.name = 'VerifivationFailed';
		throw e;
	}

	return {
		id: records[0].id,
		name: records[0].name,
		email: records[0].email
	};
};

module.exports = (service) => {

	return {
		verify: verify.bind(this, service)
	};
};
