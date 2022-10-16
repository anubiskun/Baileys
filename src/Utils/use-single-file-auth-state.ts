import { existsSync, readFileSync, writeFileSync } from 'fs'
import { proto } from '../../WAProto'
import type { AuthenticationCreds, AuthenticationState, SignalDataTypeMap } from '../Types'
import { initAuthCreds } from './auth-utils'
import { BufferJSON } from './generics'

const KEY_MAP: { [T in keyof SignalDataTypeMap]: string } = {
	'pre-key': 'preKeys',
	'session': 'sessions',
	'sender-key': 'senderKeys',
	'app-state-sync-key': 'appStateSyncKeys',
	'app-state-sync-version': 'appStateVersions',
	'sender-key-memory': 'senderKeyMemory'
}

/**
 * 
 * @param database can name json file or object/database
 * @param name 
 * @returns if use database cloud save/write database after saveCreds
 */
export const jsonFileAuth = (database: any = { }, name?: any): { state: AuthenticationState, anuCreds: () => void } => {
	let creds: AuthenticationCreds
	let keys: any = { }

	/**
    * save the authentication state to the database cloud
    */
	const saveDB = () => {
		database[name] = JSON.parse(JSON.stringify({ creds, keys }, BufferJSON.replacer, 2))
	}

	/**
    * save the authentication state in JSON file
    */
	const saveLocal = () => {
		writeFileSync(database,
			JSON.stringify({ creds, keys }, BufferJSON.replacer, 2))
	}

	if(typeof database === 'object') {
		if(name === null) {
			throw new Error("[ERROR] : parameter name can't be null")
		}

		if(typeof database[name] === 'object' && typeof database[name].creds === 'object') {
			const res = JSON.parse(JSON.stringify(database[name]), BufferJSON.reviver)
			creds = res.creds
			keys = res.keys
		} else {
			database[name] = {}
			creds = initAuthCreds()
			keys = {}
		}
	} else if(typeof database === 'string') {
		if(existsSync(database)) {
			const result = JSON.parse(readFileSync(database, { encoding: 'utf-8' }), BufferJSON.reviver)
			creds = result.creds
			keys = result.keys
		} else {
			creds = initAuthCreds()
			keys = {}
		}
	} else {
		throw new Error('Invalid database that is not a JSONFile or Database :\n' + database)
	}

	return {
		state: {
			creds,
			keys: {
				get: (type, ids) => {
					const key = KEY_MAP[type]
					return ids.reduce(
						(dict, id) => {
							let value = keys[key]?.[id]
							if(value) {
								if(type === 'app-state-sync-key') {
									value = proto.Message.AppStateSyncKeyData.fromObject(value)
								}

								dict[id] = value
							}

							return dict
						}, { }
					)
				},
				set: (data) => {
					for(const _key in data) {
						const key = KEY_MAP[_key]
						keys[key] = keys[key] || {}
						Object.assign(keys[key], data[_key])
					}

					(typeof database === 'object') ? saveDB() : saveLocal()
				}
			}
		},
		anuCreds: () => {
			(typeof database === 'object') ? saveDB() : saveLocal()
		}
	}
}