<template>
  <div id="app">
    <EncryptCommunication/>
  </div>
</template>

<script>
import EncryptCommunication from './components/EncryptCommunication.vue';

export default {
  name: 'App',
  components: {
    EncryptCommunication
  }
}
</script>


<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
