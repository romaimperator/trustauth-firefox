/**
 * This is the database code for the TrustAuth addon. This is browser specific code.
 *
 * @author Daniel Fox
 * @link trustauth.com
 * @license BSD-3 Clause License http://opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (c) 2012, Daniel Fox
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *     Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *     Neither the name of TrustAuth nor the names of its contributors may be used to endorse or promote products derived from this software
 *         without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
var EXPORTED_SYMBOLS = [ 'db' ];

Components.utils.import("chrome://trustauth/content/utils.jsm");
Components.utils.import("chrome://trustauth/content/constants.jsm");
Components.utils.import("chrome://trustauth/content/crypto.jsm");
Components.utils.import("chrome://trustauth/content/migrations.jsm");

var db = {
  version: null,
  manager: null,

  /**
   * This function wraps some SQL execution in the try...catch...finally and returns a boolean
   * result on success or failure.
   *
   * @param {string} sql string of SQL code to pass to createStatement
   * @param {function(statement)} statement_handler a function that takes the statement as a parameter and does stuff with the statement
   * @return {bool} true on success, false if there was an error
   */
  _execute: function(sql, statement_handler) {
    var db = this.connect();

    var result = false;
    try {
      var statement = db.createStatement(sql);
      if (statement_handler) { statement_handler(statement); }
      else { statement.execute(); }
      result = true;
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }
    return result;
  },

  /**
   * Fetches the database version number from the database.
   *
   * @return {int} the current migration version of the database
   */
  _get_version: function() {
    var version = null;
    this._execute("SELECT version FROM migrations", function(statement) {
      if (statement.executeStep()) {
        version = statement.row.version;
      }
    });
    return version;
  },

  /**
   * Returns the current database version number of the database. The version
   * is cached to avoid querying each call.
   *
   * @return {int} the current migration version of the database
   */
  get_version: function() {
    //return this.version;
    return this._get_version();
  },

  /**
   * Sets the version number of the database.
   *
   * @param {int} version the new version number of the database
   * @return {bool} true if update was successful, false if there was an error
   */
  set_version: function(version) {
    return this._execute("UPDATE migrations SET version=:version", function(statement) {
      statement.params.version = version;
      statement.execute();
      this.version = version;
    });
  },

  /**
   * Resets the database to before any migrations were applied.
   *
   * @return {bool} true on success, false if there was an error
   */
  reset: function() {
    return this._execute("DROP TABLE migrations");
  },

  /**
   * Creates the two migration functions for a create_table migration.
   *
   * @param {string} name the name of the new table
   * @param {hash} columns hash of columns where the key is the column name and the value is the type and any constraints
   *                       EXAMPLE: { name: "TEXT UNIQUE NOT NULL" }
   * @return {hash} hash containing the up and down functions needed for this migration
   */
  create_table: function(name, columns) {
    return {
      up: function(db) { return db._create_table(name, columns); },
      down: function(db) { return db._drop_table(name); },
    };
  },

  /**
   * Creates the two migration functions for a drop_table migration.
   *
   * @param {string} name the name of the table to drop
   * @param {hash} columns hash of columns contained in the table to allow recreation of the table. See create_table() for example
   * @return {hash} hash containing the up and down functions needed for this migration
   */
  drop_table: function(name, columns) {
    return {
      up: function(db) { return db._drop_table(name); }
      down: function(db) { return db._create_table(name, columns); }
    };
  },

  /**
   * Converts a key value pair hash into a string. Keys and values are separated by a space and pairs are separated by a comma.
   *
   * @param {hash} hash the hash to serialize
   * @return {string} string of the serialized hash
   */
  _serialize: function(hash) {
    var r = [];
    for (key in hash) {
      r.push(key + " " + hash[key]);
    }
    return r.join(',');
  },

  /**
   * Executes the database query to create a new table.
   *
   * @param {string} name the name of the table to drop
   * @param {hash} columns hash of columns contained in the table to allow recreation of the table. See create_table() for example
   * @return {bool} true on success, false if there was an error
   */
  _create_table: function(name, columns) {
    return this._execute("CREATE TABLE :name (:columns)", function(statement) {
      statement.params.name = name;
      statement.params.columns = this._serialize(columns);
      statement.execute();
    });
  },


  /**
   * Executes the database query to drop a table.
   *
   * @param {string} name the name of the table to drop
   * @return {bool} true on success, false if there was an error
   */
  _drop_table: function(name) {
    return this._execute("DROP TABLE :name", function(statement) {
      statement.params.name = name;
      statement.execute();
    });
  },

  /*
   * Connects to the database.
   */
  connect: function() {
    Components.utils.import("resource://gre/modules/Services.jsm");
    Components.utils.import("resource://gre/modules/FileUtils.jsm");

    // Establish a connection to the database
    var file = FileUtils.getFile("ProfD", ["trustauth", "trustauth.sqlite"]);
    var file_exists = file.exists();
    return Services.storage.openDatabase(file);
  },

  /**
   * Associates the given key id with the given domain id. This function fails if the key is
   * already assigned to another domain.
   *
   * @param {integer} key_id the key id to associate this domain to
   * @param {integer} site_id the id of the domain to associate this key to
   * @return {bool} true if successful; false otherwise
   */
  associate_key: function(key_id, site_id) {
    var db = this.connect();

    var result = false;
    // If this key is available then assign it to this domain
    if ( ! this.is_key_assigned(key_id)) {
      try {
        var statement = db.createStatement("INSERT INTO keys_sites (key_id, site_id) VALUES(:key_id, :site_id)");
        statement.params.key_id  = key_id;
        statement.params.site_id = site_id;
        statement.execute();
        utils.log('key associated successfully');
        result = true;
      } catch (e) {
        utils.dump(e);
        utils.log(db.lastErrorString);
      } finally {
        statement.finalize();
        db.close();
      }
    }
    return result;
  },

  /*
   * Checks to see if the given domain has a key in the database
   *
   * @param domain the domain to look for
   * @return true if the domain is in the database false otherwise
   */
  domain_exist: function(domain) {
    var db = this.connect();

    var domain_exists = false;
    try {
      // Create the statement to fetch the most recently created key for this domain
      var statement = db.createStatement("SELECT domain FROM keys, sites, keys_sites WHERE keys.id=keys_sites.key_id AND sites.id=keys_sites.site_id AND sites.domain=:domain ORDER BY keys.created DESC");

      // Bind the parameter
      statement.params.domain = domain;

      // Execute the query synchronously
      if (statement.executeStep()) {
        domain_exists = domain === statement.row.domain;
      }
    } catch (ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return domain_exists;
  },

  /**
   * Fetches the first cached key id from the database.
   */
  fetch_cache_id: function() {
    var db = this.connect();

    var key_id = null;
    try {
      var statement = db.createStatement("SELECT id FROM keys WHERE id not in (SELECT key_id FROM keys_sites) LIMIT 1");
      if (statement.executeStep()) {
        key_id = statement.row.id;
      }
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return key_id;
  },

  /*
   * Fetches the most recently created key pair for the given domain, decrypts them
   * using the encryption key and returns the pair as a hash.
   *
   * @param domain the domain to fetch keys for
   * @return hash of the public and private key pair or null if the domain doesn't have a key pair
   */
  fetch_key_pair: function(domain) {
    var db = this.connect();

    var key_pair = null;
    try {
      var statement = db.createStatement("SELECT k.id, public_key, private_key FROM keys as k, sites as s, keys_sites as ks WHERE k.id=ks.key_id AND s.id=ks.site_id AND s.domain=:domain ORDER BY k.created DESC");

      // Bind the parameter
      statement.params.domain = domain;

      // Execute the query synchronously
      if (statement.executeStep()) {
        key_pair = {
          'id': statement.row.id,
          'public_key': statement.row.public_key,
          'private_key': statement.row.private_key,
        };
      } else {
        utils.log("could not find key_pair for domain: " + domain);
      }
    } catch (ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return key_pair;
  },

  /**
   * Adds the domain name to the database and returns the site_id of the domain.
   *
   * @param {string} domain the domain name to add
   * @return {integer} the id of the either the new domain or the previously inserted domain
   */
  fetch_or_store_domain: function(domain) {
    var db = this.connect();

    // First try to insert the domain if it's not already there.
    var site_id = this.get_site_id(domain);
    if (site_id === null) {
      try {
        var statement = db.createStatement("INSERT INTO sites (domain) VALUES(:domain)");
        statement.params.domain = domain;
        statement.execute();

        site_id = db.lastInsertRowID;
      } catch (e) {
        utils.log(db.lastErrorString);
        utils.dump(e);
      } finally {
        statement.finalize();
        db.close();
      }
    }

    return site_id;
  },

  /**
   * Retrieves the hash stored in the database.
   *
   * @return {string} the hash if there is one, null otherwise
   */
  get_stored_hash: function() {
    var db = this.connect();

    var hash = null;
    try {
      var statement = db.createStatement("SELECT hash FROM password_verify LIMIT 1");

      if (statement.executeStep()) {
        hash = statement.row.hash;
      }
    } catch(ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return hash;
  },

  /*
   * Returns the site_id for the domain or null if the domain wasn't found.
   *
   * @param domain the domain to get the site_id for
   * @return the site_id
   */
  get_site_id: function(domain) {
    var db = this.connect();

    var row_id = null;
    try {
      var statement = db.createStatement("SELECT id FROM sites WHERE domain=:domain");
      statement.params.domain = domain;
      if (statement.executeStep()) {
        row_id = statement.row.id;
      }
    } catch (ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
    }

    db.close();
    return row_id;
  },

  /*
   * Initializes the place to store the public and private key pairs.
   */
  init: function() {
    this.version = this._get_version() || this.set_version(BASE_VERSION);
    this.manager = Manager(this);
    var db = this.connect();

    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, public_key TEXT, private_key TEXT, created TEXT)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, domain TEXT UNIQUE)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys_sites (key_id NUMERIC, site_id NUMERIC)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS password_verify (hash TEXT)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS migrations (version INTEGER)");
    db.executeSimpleSQL("INSERT INTO migrations (version) VALUES (" + BASE_VERSION + ")");

    db.close();
  },

  /**
   * Checks to see if the key_id is already assigned to a domain.
   *
   * @param {integer} key_id the key id to check
   * @return {bool} true if the key is assigned already; false otherwise
   */
  is_key_assigned: function(key_id) {
    var db = this.connect();

    var result = false;
    try {
      var statement = db.createStatement("SELECT * FROM keys_sites WHERE key_id=:key_id");
      statement.params.key_id = key_id;

      if (statement.executeStep()) {
        if (statement.row.key_id) {
          result = true;
        }
      }
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
      result = true;
    } finally {
      statement.finalize();
      db.close();
    }

    return result;
  },

  /**
   * Stores a cache key in the database for future use.
   *
   * @param {forge key objects} keys the key pair to store as the next cache key.
   */
  store_cache_pair: function(public_key, private_key) {
    var db = this.connect();

    var result = false;
    try {
      var statement = db.createStatement("INSERT INTO keys (public_key, private_key, created) VALUES(:public_key, :private_key, :created)");
      statement.params.public_key  = public_key;
      statement.params.private_key = private_key;
      statement.params.created     = utils.get_time();
      if (statement.executeStep()) result = true;
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return result;
  },

  /*
   * This function stores the key in the browser's password manager
   *
   * @param key the key to store
   */
  store_encryption_key: function(key) {
    var success = false;
    if (! is_password_set()) {
      var db = this.connect();

      try {
        var statement = db.createStatement("INSERT OR ABORT INTO password_verify (hash) VALUES(:hash)");
        statement.params.hash = this.get_storage_hash(key);

        success = statement.executeStep();
      } catch (ex) {
        utils.dump(ex);
        utils.log(db.lastErrorString);
      } finally {
        statement.finalize();
        db.close();
      }

    }
    return success;
  },

};
