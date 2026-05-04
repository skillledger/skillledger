import createClient from "openapi-react-query"
import { fetchClient } from "./api-client"

export const $api = createClient(fetchClient)
