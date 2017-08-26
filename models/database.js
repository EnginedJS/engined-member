const Joi = require('joi');

module.exports = {
	Member: {
		columns: {
			id: Joi.number().integer().positive().required().default('AUTO_INCREMENT'),
			name: Joi.string().max(255).required(),
			email: Joi.string().email().max(512).required(),
			password: Joi.string().required(),
			salt: Joi.string().required(),
			phone: Joi.string().max(64),
			avatar_url: Joi.string().max(255),
			country: Joi.string().max(255),
			address: Joi.string().max(255),
			city: Joi.string().max(255),
			state: Joi.string().max(255),
			zip_code: Joi.string().max(64),
			disabled: Joi.number().integer().max(1).default(0),
			created: Joi.date().default('CURRENT_TIMESTAMP')
		},
		indexes: {
			PRIMARY: {
				type: 'primary',
				columns: [
					'id'
				]
			},
			email: {
				type: 'unique',
				columns: [
					'email'
				]
			}
		}
	},
	MemberPermission: {
		columns: {
			id: Joi.number().integer().positive().required().default('AUTO_INCREMENT'),
			member: Joi.number().integer().positive().required(),
			groupName: Joi.string().max(255).required(),
			signature: Joi.string().max(255).required()
		},
		indexes: {
			PRIMARY: {
				type: 'primary',
				columns: [
					'id'
				]
			},
			permission: {
				type: 'unique',
				columns: [
					'member',
					'groupName',
					'signature'
				]
			}
		}
	}
};
