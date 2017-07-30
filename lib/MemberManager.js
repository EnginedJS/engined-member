const Joi = require('joi');

module.exports = class {

	constructor(memberAgent) {
		this.memberAgent = memberAgent;
	}

	async isDisabled(memberId) {

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'SELECT `disabled`',
			'FROM `Member`',
			'WHERE',
			'`id` = ?',
			'LIMIT 1'
		].join(' ');
		let [ records ] = await dbAgent.query(qstr, [ memberId ]);

		// Member doesn't exist
		if (records[0].length === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}

		// Account was disabled
		if (records[0].disabled)
			return true;

		return false;

	}

	async verify(memberPass) {

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		let value;
		try {
			// Validate
			value = await new Promise((resolve, reject) => {

				Joi.validate(memberPass, this.memberAgent.getSchemaChecker('verify'), (err, value) => {
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
			'`email` = ?',
			'LIMIT 1'
		].join(' ');
		let [ records ] = await dbAgent.query(qstr, [ value.email ]);
		if (records[0].length === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}

		// Check password
		if (this.memberAgent.encryptPassword(records[0].salt, value.password) !== records[0].password) {
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
	}

	async createMember(memberInfo) {

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Create member
		let ret;
		try {
			// Validate
			let value = await new Promise((resolve, reject) => {

				Joi.validate(memberInfo, this.memberAgent.getSchemaChecker('createMember'), (err, value) => {
					if (err)
						return reject(err);

					resolve(value);
				});
			});

			// Encrypt password
			value.salt = this.memberAgent.generateSalt();
			value.password = this.memberAgent.encryptPassword(value.salt, value.password);

			// Is account disabled by default?
			if (this.memberAgent.getOptions().accountIsDisabledByDefault) {
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
	}

	async getProfile(memberId) {

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'SELECT `id`, `name`, `email`, `disabled`',
			'FROM `Member`',
			'WHERE',
			'`id` = ?',
			'LIMIT 1'
		].join(' ');
		let [ records ] = await dbAgent.query(qstr, [ memberId ]);
		if (records[0].length === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}

		return records[0];
	}
};
