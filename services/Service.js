const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Service, AgentManager } = require('engined');
const Agent = require('../lib/Agent');
const {
	database,
	view,
	validation
} = require('../models');

module.exports = (opts = {}) => {

	const PrototypeService = Service.create({
		DataModel: {
			Database: database,
			View: view,
			Validation: validation
		}
	});

	class Member extends PrototypeService {

		constructor(context) {
			super(context);

			this.dependencies = [
				'Storage',
				'MySQL'
			];
			this.agent = null;
			this.opts = opts;
			this.agentName = opts.agentName || 'default';
		}

		async start() {

			// Add agent
			this.agent = new Agent(this);

			await this.agent.initialize();

			// Register on context object
			this.getContext()
				.assert('Member')
				.register(this.agentName, this.agent);
		}

		async stop() {

			if (this.agent === null)
				return;

			this.agent = null;

			// Getting agent member
			let agentManager = this.getContext().get('Member');
			if (!agentManager)
				return;

			// Take off agent from context
			agentManager.unregister(this.agentName);

			if (agentManager.count() === 0)
				this.getContext().remove('Member');
		}
	}

	return Member;
};
