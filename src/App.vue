<script lang="ts">
import { defineComponent } from "vue";
import { invoke } from "@tauri-apps/api/tauri";
import { appWindow } from "@tauri-apps/api/window";

export default defineComponent({
  name: "App",

  components: {},

  data: () => {
    return {

      loading: false,

      me: { email: "", name: "", picture: "" },

      title: "Tari + oauth example",

    };
  },
  computed: {},

  async created() {
    console.log(`MainLayout created()`);

    this.loading = true;

    await this.on_login();

  },

  methods: {
    async on_login() {
      const that = this;
      invoke("js2rs", {
        message: "get_user"
      }).then((data: any) => {
        try {
          let me_data = JSON.parse(data)
          that.me.name = me_data.name ? me_data.name : "";
          that.me.email = me_data.email ? me_data.email : "";
        } catch (err) {
          console.error(err);
        }
        that.loading = false;
      });
    },

    async on_logout() {
      const that = this;
      this.me = { email: "", name: "", picture: "" };
      invoke("js2rs", {
        message: "logout"
      }).then((data: any) => {
        try {
          let me_data = JSON.parse(data)
          that.me.name = me_data.name ? me_data.name : "";
          that.me.email = me_data.email ? me_data.email : "";
        } catch (err) {
          console.error(err);
        }
        that.loading = false;
      });
    },

    async on_end() {
      await appWindow.close();
    },    

  },

});
</script>

<style>
.button {
  border: none;
  color: white;
  padding: 15px 32px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 16px;
  margin: 4px 2px;
  cursor: pointer;
}
</style>

<template>
  <div>
    Name: {{ me.name }} <br>
    Email: {{ me.email }}
  </div>
  <div>
    <button v-if="me.email == ''"  type="button" @click="on_login()" style="background-color: green;">Log in</button>
    <button v-if="me.email != ''"  type="button" @click="on_logout()" style="background-color: red;">Log out</button>
    <button type="button" @click="on_end()" style="background-color: black;">End</button>
  </div>
</template>