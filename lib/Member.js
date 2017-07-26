

const verify = async (service, email, password) => {

	// Getting member system agent
	let agent = service.getContext().get('Member')[service.memberAgent];

	// Getting database agent
	let dbAgent = service.getContext().get('MySQL')[agent.dbAgentName];

	// Finding member by using email
	let qstr = [
		'SELECT `id`, `name`, `email`, `salt`, `password`, `disabled`',
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
		let e = new Error('Password is incorrect');
		e.name = 'VerifivationFailed';
		throw e;
	}

	// Account is disabled
	if (records[0].disabled === 1) {
		let e = new Error('Account is disabled');
		e.name = 'Disabled';
		throw e;
	}

	return {
		id: records[0].id,
		name: records[0].name,
		email: records[0].email
	};
};

const createMember = async (service, email, password) => {

	// Getting member system agent
	let agent = service.getContext().get('Member')[service.memberAgent];

	// Getting database agent
	let dbAgent = service.getContext().get('MySQL')[agent.dbAgentName];

	// Encrypt password
	let salt = agent.generateSalt();
	let _password = agent.encryptPassword(salt, password);

	// Create member
	let ret;
	try {
		[ ret ] = await dbAgent.query('INSERT INTO `Member` SET ?', {
			email: email,
			password: _password,
			salt: salt
		});
	} catch(e) {

		// Account exists already
		if (e.code === 'ER_DUP_ENTRY') {
			let e = new Error('Account exists already');
			e.name = 'MemberExists';
			throw e;
		}

		throw e;
	}

	if (ret.affectedRows === 0) {
		// Failed to insert record
		let e = new Error('Failed to create member');
		e.name = 'MemberCreationFailed';
		throw e;
	}

	return ret.insertId;
};

module.exports = (service) => {

	return {
		verify: verify.bind(this, service),
		createMember: createMember.bind(this, service)
	};
};
