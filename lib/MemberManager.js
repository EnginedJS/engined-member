const Joi = require('joi');
const uuidv1 = require('uuid/v1');
const mime = require('mime');
const crypto = require('crypto');

module.exports = class {

	constructor(memberAgent) {
		this.memberAgent = memberAgent;
	}

	async checkMemberByEmail(email) {

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'SELECT `id`, `disabled`',
			'FROM `Member`',
			'WHERE',
			'`email` = ?',
			'LIMIT 1'
		].join(' ');
		let [ records ] = await dbAgent.query(qstr, [ email ]);

		// Member doesn't exist
		if (records[0].length === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}

		// Account was disabled
		if (records[0].disabled) {
			let e = new Error('Account was blocked');
			e.name = 'Disabled';
			throw e;
		}
		
		return {
			id: records[0].id
		};
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

	async getLoginInfo(memberId) {

		// Getting view
		let view = this.memberAgent.getView('GetLoginInfo');

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using ID
		let qstr = [
			'SELECT',
			view.prepareColumns(),
			'FROM',
			view.prepareTables(),
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

	async verifyMember(memberPass) {

		// Getting view
		let view = this.memberAgent.getView('VerifyMember');

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Validate fields
		let validator = this.memberAgent.getContext().get('Validator');
		let validationRules = this.memberAgent.getValidationRules('VerifyMember');
		let value = await validator.validate(validationRules, memberPass);

		// Prepare required columns
		let columns = [
			[
				'Member.email as email',
				'Member.password as password',
				'Member.salt as salt',
				'Member.disabled as disabled'
			].join(', '),
			view.prepareColumns()
		];

		// Finding member by using email
		let qstr = [
			'SELECT',
			columns.join(', '),
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
			e.name = 'VerificationFailed';
			throw e;
		}

		// Account is disabled
		if (records[0].disabled === 1) {
			let e = new Error('Account is disabled');
			e.name = 'Disabled';
			throw e;
		}

		return view.getFieldNames().reduce((result, viewFieldName) => {
			result[viewFieldName] = records[0][viewFieldName];
			return result;
		}, {});
	}

	async verifyPasswordById(memberId, password) {

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'SELECT `password`, `salt`, `disabled`',
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

		// Check password
		if (this.memberAgent.encryptPassword(records[0].salt, password) !== records[0].password) {
			let e = new Error('Password is incorrect');
			e.name = 'VerificationFailed';
			throw e;
		}

		// Account is disabled
		if (records[0].disabled === 1) {
			let e = new Error('Account is disabled');
			e.name = 'Disabled';
			throw e;
		}
	}

	async createMember(memberInfo) {

		// Getting view
		let view = this.memberAgent.getView('CreateMember');

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Validate fields
		let validator = this.memberAgent.getContext().get('Validator');
		let validationRules = this.memberAgent.getValidationRules('CreateMember');
		let value = await validator.validate(validationRules, memberInfo);

		// Create member
		let ret;
		try {

			// Encrypt password
			value.salt = this.memberAgent.generateSalt();
			value.password = this.memberAgent.encryptPassword(value.salt, value.password);

			// Is account disabled by default?
			if (this.memberAgent.getOptions().accountIsDisabledByDefault) {
				value.disabled = 1;
			}

			[ ret ] = await dbAgent.query('INSERT INTO `Member` SET ?', value);
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
	}

	async getFullProfile(memberId) {

		// Getting view
		let view = this.memberAgent.getView('GetFullProfile');

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'SELECT',
			view.prepareColumns(),
			'FROM',
			view.prepareTables(),
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

	async getProfile(memberId) {

		// Getting view
		let view = this.memberAgent.getView('GetProfile');

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using ID
		let qstr = [
			'SELECT',
			view.prepareColumns(),
			'FROM',
			view.prepareTables(),
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

	async updateProfile(memberId, profile) {

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Validate fields
		let validator = this.memberAgent.getContext().get('Validator');
		let validationRules = this.memberAgent.getValidationRules('UpdateProfile');
		let value = await validator.validate(validationRules, profile);

		// Getting view
		let view = this.memberAgent.getView('UpdateProfile');

		// Finding member by using ID
		let qstr = [
			'UPDATE',
			view.prepareTables(),
			'SET',
			view.getFieldNames().map((name) => {
				if (profile[name] === undefined)
					return null;

				return name + ' = ?';
			}).filter(value => (value !== null)).join(', '),
			'WHERE Member.id = ?',
			'LIMIT 1'
		].join(' ');
		let [ ret ] = await dbAgent.query(qstr, Object.values(profile).concat([ memberId ]));
		if (ret.affectedRows === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}

		return value;
	}

	async updatePassword(memberId, password) {

		// Encrypt password
		let salt = this.memberAgent.generateSalt();
		let newPassword = this.memberAgent.encryptPassword(salt, password);

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'UPDATE `Member`',
			'SET `password` = ?, `salt` = ?',
			'WHERE',
			'`id` = ?',
			'LIMIT 1'
		].join(' ');
		let [ ret ] = await dbAgent.query(qstr, [ newPassword, salt, memberId ]);
		if (ret.affectedRows === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}
	}

	async updatePasswordByEmail(email, password) {

		// Encrypt password
		let salt = this.memberAgent.generateSalt();
		let newPassword = this.memberAgent.encryptPassword(salt, password);

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'UPDATE `Member`',
			'SET `password` = ?, `salt` = ?',
			'WHERE',
			'`email` = ?',
			'LIMIT 1'
		].join(' ');
		let [ ret ] = await dbAgent.query(qstr, [ newPassword, salt, email ]);
		if (ret.affectedRows === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}
	}

	async changePassword(memberId, oldPassword, newPassword) {

		// Nothing's changed
		if (oldPassword === newPassword) {
			return;
		}

		try {
			// Verify old password
			await this.verifyPasswordById(memberId, oldPassword);

			// Update password right now
			await this.updatePassword(memberId, newPassword);
		} catch(e) {

			switch(e.name) {
			case 'VerificationFailed':
				let e = new Error('Old password is incorrect');
				e.name = 'IncorrectOldPassword';
				throw e;
			}

			throw e;
		}
	}

	async updateAvatarByStream(memberId, dataInfo, stream) {

		// Getting storage agent
		let storageAgent = this.memberAgent.getContext().get('Storage').getAgent(this.memberAgent.options.storageAgent);

		// Saving data
		let size = dataInfo.size || 0;
		let extension = mime.extension(dataInfo.contentType);
		let filename = uuidv1() + '.' + extension;
		let avatarUrl = await new Promise((resolve, reject) => {

			// Save
			let storageTask = storageAgent.save(stream, filename, size);

			storageTask.on('error', (err) => {
				let e = new Error('Storage failed');
				e.name = 'StorageFailed';
				reject(e);
			});

			storageTask.on('complete', (url) => {
				resolve(url);
			});
		});

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Finding member by using email
		let qstr = [
			'UPDATE `Member`',
			'SET `avatar_url` = ?',
			'WHERE',
			'`id` = ?',
			'LIMIT 1'
		].join(' ');
		let [ ret ] = await dbAgent.query(qstr, [ avatarUrl, memberId ]);
		if (ret.affectedRows === 0) {
			let e = new Error('No such member');
			e.name = 'NotExist';
			throw e;
		}

		return avatarUrl;
	}

	async sendPasswordResetEmail(payload) {

		// Validate fields
		let validator = this.memberAgent.getContext().get('Validator');
		let validationRules = this.memberAgent.getValidationRules('SendPasswordResetEmail');
		let value = await validator.validate(validationRules, payload);

		// Check account by email
		let member = await this.checkMemberByEmail(value.email);

		// Generate token for reset password
		let token = this.memberAgent.generateJwtToken({
			email: value.email,
			perms: [
				'Member.reset.password'
			]
		});

		// TODO: send password reset email
console.log(token);

		return token;
	}

	async listMembers(conditions = {}, page = 1, perPage = 50) {

		// Getting view
		let view = this.memberAgent.getView('ListMembers');

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Preparing conditions
		let queryConditions = Object.entries(conditions)
			.reduce((result, field, value) => {

				result.conditions.push(view.getColumnName(field) + ' = ?');
				result.params.push(value);

				return result;
			}, { conditions: [], params: [] });

		// Finding member by using email
		let qstr = [
			'SELECT',
			view.prepareColumns(),
			'FROM',
			view.prepareTables(),
			queryConditions.conditions.length ? 'WHERE' : '',
			queryConditions.conditions.join(', '),
			'LIMIT ?,?'
		].join(' ');
		let [ records, info ] = await dbAgent.query(qstr, queryConditions.params.concat([ (page - 1) * perPage, perPage ]));

		return records;
	}

	async countMembers(conditions) {

		// Getting view
		let view = this.memberAgent.getView('ListMembers');

		// Getting database agent
		let dbAgent = this.memberAgent.getContext().get('MySQL')[this.memberAgent.dbAgent];

		// Preparing conditions
		let queryConditions = Object.entries(conditions)
			.reduce((result, field, value) => {

				result.conditions.push(view.getColumnName(field) + ' = ?');
				result.params.push(value);

				return result;
			}, { conditions: [], params: [] });

		// Finding member by using email
		let qstr = [
			'SELECT COUNT(*) as total',
			'FROM',
			view.prepareTables(),
			queryConditions.conditions.length ? 'WHERE' : '',
			queryConditions.conditions.join(', ')
		].join(' ');
		let [ records ] = await dbAgent.query(qstr, queryConditions.params);

		return records[0].total;

	}
};
