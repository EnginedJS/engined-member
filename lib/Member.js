const Joi = require('joi');

const verify = async (service, memberPass) => {

	// Getting member system agent
	let agent = service.getContext().get('Member')[service.memberAgent];

	// Getting database agent
	let dbAgent = service.getContext().get('MySQL')[agent.dbAgent];

	let value;
	try {
		// Validate
		value = await new Promise((resolve, reject) => {

			Joi.validate(memberPass, agent.getSchemaChecker('verify'), (err, value) => {
				if (err)
					return reject(err);

				resolve(value);
			});
		});
	} catch(e) {

		switch(e.name) {
		case 'ValidationError':
			let err = new Error(e.name);
			err.name = 'ValidationFailed';
			err.errors = e.details.map((error) => {
				return {
					field: error.path,
					type: error.type
				};
			});
			throw err;
		}

		throw e;
	}

	// Finding member by using email
	let qstr = [
		'SELECT `id`, `name`, `email`, `salt`, `password`, `disabled`',
		'FROM `Member`',
		'WHERE',
		'`email` = ?'
	].join(' ');
	let [ records ] = await dbAgent.query(qstr, [ value.email ]);
	if (records[0].length === 0) {
		let e = new Error('No such member');
		e.name = 'NotExist';
		throw e;
	}

	// Check password
	if (agent.encryptPassword(records[0].salt, value.password) !== records[0].password) {
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

const createMember = async (service, memberInfo) => {

	// Getting member system agent
	let agent = service.getContext().get('Member')[service.memberAgent];

	// Getting database agent
	let dbAgent = service.getContext().get('MySQL')[agent.dbAgent];

	// Create member
	let ret;
	try {
		// Validate
		let value = await new Promise((resolve, reject) => {

			Joi.validate(memberInfo, agent.getSchemaChecker('createMember'), (err, value) => {
				if (err)
					return reject(err);

				resolve(value);
			});
		});

		// Encrypt password
		value.salt = agent.generateSalt();
		value.password = agent.encryptPassword(value.salt, value.password);

		// Is account disabled by default?
		if (agent.getOptions().accountIsDisabledByDefault) {
			value.disabled = 1;
		}

		[ ret ] = await dbAgent.query('INSERT INTO `Member` SET ?', value);
	} catch(e) {

		switch(e.name) {
		case 'ValidationError':
			let err = new Error(e.name);
			err.name = 'ValidationFailed';
			err.errors = e.details.map((error) => {
				return {
					field: error.path,
					type: error.type
				};
			});
			throw err;
		}

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
